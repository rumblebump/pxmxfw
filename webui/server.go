package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	idleTimeout   = 30 * time.Minute
	maxSessionAge = 12 * time.Hour
	stepUpWindow  = 5 * time.Minute
	cookieName    = "__Host-pxmxfw"
	maxBody       = 64 << 10
	cmdTimeout    = 2 * time.Minute
	pkgTimeout    = 10 * time.Minute // apk add/upgrade over a slow link
)

// failDelay slows down password and code guessing (tests set it to zero).
var failDelay = time.Second

type authenticator interface {
	Authenticate(user, pass string) error
}

type server struct {
	st      *store
	auth    authenticator
	allowed func(user string) bool
	pxmxfw  string // path of the pxmxfw command
	etc     string // /etc/pxmxfw
	leases  string
	www     string
	host    string
	now     func() time.Time
	limit   *limiter
	flows   flowStore  // pending security key requests
	mu      sync.Mutex // serialises config changes
}

// principal is who a request acts as: a browser session or an access token.
type principal struct {
	user    string
	session string // cookie token, empty for access tokens
	scope   string // "session", "read" or "write"
}

func (p *principal) viaToken() bool { return p.session == "" }

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api", s.api)
	files := http.FileServer(http.Dir(s.www))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r) // no directory listings
			return
		}
		files.ServeHTTP(w, r)
	})
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// Alpine.js evaluates its directives with Function(), hence unsafe-eval
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-eval'; "+
			"style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func text(w http.ResponseWriter, code int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	io.WriteString(w, body)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// identify finds the session cookie or bearer token of a request.
func (s *server) identify(r *http.Request) *principal {
	now := s.now()
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		user, scope, ok := s.st.tokenUser(strings.TrimPrefix(h, "Bearer "), now)
		if !ok || !s.allowed(user) {
			return nil
		}
		return &principal{user: user, scope: scope}
	}
	c, err := r.Cookie(cookieName)
	if err != nil {
		return nil
	}
	user, ok := s.st.session(c.Value, now)
	if !ok || !s.allowed(user) {
		return nil
	}
	return &principal{user: user, session: c.Value, scope: "session"}
}

// API: GET/POST /api?action=NAME[&name=...]. Replies are plain text, like the
// pxmxfw command's own output; errors carry the message as the body.
func (s *server) api(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		text(w, http.StatusMethodNotAllowed, "use GET or POST\n")
		return
	}
	q := r.URL.Query()
	action, name := q.Get("action"), q.Get("name")
	key := r.Method + ":" + action

	var body []byte
	if r.Method == http.MethodPost {
		var err error
		body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			text(w, http.StatusRequestEntityTooLarge, "request too large\n")
			return
		}
	}

	p := s.identify(r)
	// Browsers do not send custom headers cross-site without a CORS
	// preflight, which this never answers, so other pages cannot make a
	// logged-in browser change anything. Tokens are not sent by browsers.
	if r.Method == http.MethodPost && (p == nil || !p.viaToken()) && r.Header.Get("X-Pxmxfw") != "1" {
		text(w, http.StatusForbidden, "missing X-Pxmxfw header\n")
		return
	}
	if key == "POST:login" {
		s.login(w, r, body)
		return
	}
	if p == nil {
		text(w, http.StatusUnauthorized, "login required\n")
		return
	}
	if p.viaToken() {
		switch {
		case !tokenActions[key]:
			text(w, http.StatusForbidden, "not available with an access token\n")
			return
		case r.Method == http.MethodPost && p.scope != "write":
			text(w, http.StatusForbidden, "read-only token\n")
			return
		}
	}

	switch key {
	case "GET:status":
		s.run(w, "status")
	case "GET:check":
		s.run(w, "check", "--tsv")
	case "GET:file":
		s.getFile(w, name)
	case "GET:leases":
		b, _ := os.ReadFile(s.leases)
		text(w, http.StatusOK, string(b))
	case "GET:me":
		s.me(w, r, p)
	case "GET:prefs":
		s.getPrefs(w)
	case "GET:audit":
		s.getAudit(w)
	case "GET:tokens":
		s.listTokens(w, p)
	case "POST:logout":
		s.st.endSession(p.session)
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		text(w, http.StatusOK, "logged out\n")
	case "GET:propose-subnet":
		s.proposeSubnet(w, p, name)
	case "GET:pkgs":
		s.run(w, "pkg-list")
	case "GET:pkg-search":
		out, err := s.command("pkg-search", name)
		if err != nil {
			text(w, http.StatusBadRequest, string(out))
			return
		}
		text(w, http.StatusOK, string(out))
	case "POST:pkg-add", "POST:pkg-del", "POST:pkg-sync", "POST:pkg-upgrade":
		if s.requireStepUp(w, r, p) {
			s.packages(w, p, action, name)
		}
	case "POST:wgkeypair":
		// a fresh WireGuard key pair for a peer config; nothing is stored
		out, err := s.command("wg-keypair")
		if err != nil {
			text(w, http.StatusInternalServerError, string(out))
			return
		}
		text(w, http.StatusOK, string(out))
	case "POST:pref":
		s.setPref(w, name, string(body))
	case "POST:stepup-begin":
		fr, err := s.beginAssertion(r, "stepup", p.user, p.session)
		if err != nil {
			text(w, http.StatusBadRequest, err.Error()+"\n")
			return
		}
		jsonReply(w, http.StatusOK, fr)
	case "POST:stepup":
		s.stepUp(w, r, p, body)
	case "GET:keys":
		s.listKeys(w, r, p)
	case "POST:key-register-begin":
		if s.requireStepUp(w, r, p) {
			s.keyRegisterBegin(w, r, p, body)
		}
	case "POST:key-register-finish":
		s.keyRegisterFinish(w, r, p, name, body)
	case "POST:key-delete":
		if s.requireStepUp(w, r, p) {
			if !s.st.deleteKey(p.user, name) {
				text(w, http.StatusNotFound, "no such key\n")
				return
			}
			s.st.log(s.now(), p.user, "key", "deleted "+name)
			text(w, http.StatusOK, "deleted\n")
		}
	case "POST:save":
		if s.requireStepUp(w, r, p) {
			s.save(w, p, name, body)
		}
	case "POST:apply":
		if s.requireStepUp(w, r, p) {
			s.apply(w, p)
		}
	case "POST:totp-setup":
		s.totpSetup(w, p)
	case "POST:totp-enable":
		s.totpEnable(w, p, body)
	case "POST:totp-disable":
		if s.requireStepUp(w, r, p) {
			s.st.deleteTOTP(p.user)
			s.st.log(s.now(), p.user, "totp", "disabled")
			text(w, http.StatusOK, "two-factor login disabled\n")
		}
	case "POST:token-create":
		if s.requireStepUp(w, r, p) {
			s.createToken(w, p, body)
		}
	case "POST:token-delete":
		id, _ := strconv.ParseInt(name, 10, 64)
		if !s.st.deleteToken(p.user, id) {
			text(w, http.StatusNotFound, "no such token\n")
			return
		}
		s.st.log(s.now(), p.user, "token", "deleted "+name)
		text(w, http.StatusOK, "deleted\n")
	default:
		text(w, http.StatusNotFound, "unknown action\n")
	}
}

// Access tokens are for automation: read state and change the config, but
// not manage logins, factors or other tokens.
var tokenActions = map[string]bool{
	"GET:status": true, "GET:check": true, "GET:file": true, "GET:leases": true,
	"GET:me": true, "POST:save": true, "POST:apply": true,
	"GET:pkgs": true, "POST:pkg-sync": true,
}

// ---- login, step-up, TOTP ----

type credentials struct {
	User      string          `json:"user"`
	Password  string          `json:"password"`
	Code      string          `json:"code"`
	Flow      string          `json:"flow"`      // security key request ...
	Assertion json.RawMessage `json:"assertion"` // ... and the browser's answer
}

func (s *server) login(w http.ResponseWriter, r *http.Request, body []byte) {
	var c credentials
	if json.Unmarshal(body, &c) != nil || c.User == "" || c.Password == "" {
		text(w, http.StatusBadRequest, "user and password required\n")
		return
	}
	ip := clientIP(r)
	if !s.limit.allow("ip:"+ip) || !s.limit.allow("user:"+c.User) {
		text(w, http.StatusTooManyRequests, "too many failed logins, try again in a few minutes\n")
		return
	}
	now := s.now()
	fail := func() {
		s.limit.fail("ip:" + ip)
		s.limit.fail("user:" + c.User)
		s.st.log(now, c.User, "login", "failed from "+ip)
		time.Sleep(failDelay)
		text(w, http.StatusUnauthorized, "wrong user name, password or code\n")
	}
	if s.auth.Authenticate(c.User, c.Password) != nil || !s.allowed(c.User) {
		fail()
		return
	}
	methods := s.secondFactors(r, c.User)
	used2FA := false
	switch {
	case len(methods) == 0:
	case slices.Contains(methods, "webauthn") && c.Flow != "":
		if err := s.finishAssertion(r, "login", c.User, "", c.Flow, c.Assertion); err != nil {
			fail()
			return
		}
		used2FA = true
	case slices.Contains(methods, "totp") && strings.TrimSpace(c.Code) != "":
		secret, _ := s.st.totpSecret(c.User)
		step, ok := totpMatch(secret, c.Code, now)
		if !ok || !s.st.useTOTPStep(c.User, step) {
			fail()
			return
		}
		used2FA = true
	default:
		// the password was right; ask for the second factor
		w.Header().Set("X-Pxmxfw-Need", strings.Join(methods, ","))
		reply := map[string]any{"need": methods}
		if slices.Contains(methods, "webauthn") {
			if fr, err := s.beginAssertion(r, "login", c.User, ""); err == nil {
				reply["flow"], reply["options"] = fr.Flow, fr.Options
			}
		}
		jsonReply(w, http.StatusUnauthorized, reply)
		return
	}
	token, err := s.st.newSession(c.User, now)
	if err != nil {
		text(w, http.StatusInternalServerError, "could not create a session\n")
		return
	}
	if used2FA {
		s.st.setStepUp(token, now.Add(stepUpWindow))
	}
	s.limit.reset("ip:" + ip)
	s.limit.reset("user:" + c.User)
	s.st.log(now, c.User, "login", "from "+ip)
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: token, Path: "/", MaxAge: int(maxSessionAge / time.Second),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	text(w, http.StatusOK, "logged in\n")
}

// secondFactors lists what the user has besides the password: security
// keys registered for the host name in use, and TOTP.
func (s *server) secondFactors(r *http.Request, user string) []string {
	var m []string
	if _, rpid, err := rpFor(r); err == nil && s.st.keyCount(user, rpid) > 0 {
		m = append(m, "webauthn")
	}
	if _, on := s.st.totpSecret(user); on {
		m = append(m, "totp")
	}
	return m
}

// stepUpMethods is what a user confirms changes with: a second factor, or
// the password when there is none.
func (s *server) stepUpMethods(r *http.Request, user string) []string {
	if m := s.secondFactors(r, user); len(m) > 0 {
		return m
	}
	return []string{"password"}
}

// requireStepUp lets a change through when the session confirmed a second
// factor (or the password, without one) in the last few minutes.
func (s *server) requireStepUp(w http.ResponseWriter, r *http.Request, p *principal) bool {
	if p.viaToken() || s.st.steppedUp(p.session, s.now()) {
		return true
	}
	w.Header().Set("X-Pxmxfw-Stepup", strings.Join(s.stepUpMethods(r, p.user), ","))
	text(w, http.StatusForbidden, "confirm this change first\n")
	return false
}

func (s *server) stepUp(w http.ResponseWriter, r *http.Request, p *principal, body []byte) {
	var c credentials
	json.Unmarshal(body, &c)
	now := s.now()
	lk := "stepup:" + p.user
	if !s.limit.allow(lk) {
		text(w, http.StatusTooManyRequests, "too many failed attempts, try again in a few minutes\n")
		return
	}
	methods := s.stepUpMethods(r, p.user)
	ok := false
	switch {
	case slices.Contains(methods, "webauthn") && c.Flow != "":
		ok = s.finishAssertion(r, "stepup", p.user, p.session, c.Flow, c.Assertion) == nil
	case slices.Contains(methods, "totp") && c.Code != "":
		secret, _ := s.st.totpSecret(p.user)
		step, match := totpMatch(secret, c.Code, now)
		ok = match && s.st.useTOTPStep(p.user, step)
	case slices.Contains(methods, "password"):
		ok = c.Password != "" && s.auth.Authenticate(p.user, c.Password) == nil
	}
	if !ok {
		s.limit.fail(lk)
		s.st.log(now, p.user, "confirm", "failed from "+clientIP(r))
		time.Sleep(failDelay)
		text(w, http.StatusForbidden, "not confirmed: wrong key, code or password\n")
		return
	}
	s.limit.reset(lk)
	s.st.setStepUp(p.session, now.Add(stepUpWindow))
	text(w, http.StatusOK, "confirmed\n")
}

func (s *server) totpSetup(w http.ResponseWriter, p *principal) {
	if _, on := s.st.totpSecret(p.user); on {
		text(w, http.StatusConflict, "two-factor login is already on; turn it off first\n")
		return
	}
	secret, err := newTOTPSecret()
	if err == nil {
		err = s.st.setPendingTOTP(p.user, secret)
	}
	if err != nil {
		text(w, http.StatusInternalServerError, "could not create a secret\n")
		return
	}
	text(w, http.StatusOK, fmt.Sprintf("secret=%s\nuri=%s\n", secret, totpURI(secret, p.user, s.host)))
}

func (s *server) totpEnable(w http.ResponseWriter, p *principal, body []byte) {
	var c credentials
	json.Unmarshal(body, &c)
	secret, on := s.st.totpSecret(p.user)
	if secret == "" || on {
		text(w, http.StatusConflict, "start the setup first\n")
		return
	}
	now := s.now()
	step, ok := totpMatch(secret, c.Code, now)
	if !ok || !s.st.useTOTPStep(p.user, step) {
		text(w, http.StatusBadRequest, "that code does not match; check the time on your phone\n")
		return
	}
	s.st.enableTOTP(p.user)
	s.st.setStepUp(p.session, now.Add(stepUpWindow))
	s.st.log(now, p.user, "totp", "enabled")
	text(w, http.StatusOK, "two-factor login enabled\n")
}

func (s *server) me(w http.ResponseWriter, r *http.Request, p *principal) {
	var b strings.Builder
	fmt.Fprintf(&b, "user=%s\nvia=%s\n", p.user, p.scope)
	if !p.viaToken() {
		secret, on := s.st.totpSecret(p.user)
		state := "off"
		if on {
			state = "on"
		} else if secret != "" {
			state = "pending"
		}
		fmt.Fprintf(&b, "totp=%s\nconfirm=%s\n", state, strings.Join(s.stepUpMethods(r, p.user), ","))
		if _, rpid, err := rpFor(r); err == nil {
			fmt.Fprintf(&b, "keys=%d\nrpid=%s\n", s.st.keyCount(p.user, rpid), rpid)
		} else {
			fmt.Fprintf(&b, "keys_unavailable=%s\n", err)
		}
		var until int64
		s.st.db.QueryRow(`SELECT stepup_until FROM sessions WHERE token_hash = ?`, hashToken(p.session)).Scan(&until)
		if left := until - s.now().Unix(); left > 0 {
			fmt.Fprintf(&b, "confirmed_for=%d\n", left)
		}
	}
	text(w, http.StatusOK, b.String())
}

// ---- access tokens ----

var tokenNameRE = regexp.MustCompile(`^[A-Za-z0-9 ._-]{1,40}$`)

func (s *server) createToken(w http.ResponseWriter, p *principal, body []byte) {
	var req struct {
		Name  string `json:"name"`
		Scope string `json:"scope"`
		Days  int    `json:"days"`
	}
	if json.Unmarshal(body, &req) != nil || !tokenNameRE.MatchString(req.Name) ||
		(req.Scope != "read" && req.Scope != "write") || req.Days < 1 || req.Days > 3650 {
		text(w, http.StatusBadRequest, "name (letters, digits, space . _ -), scope read or write, and 1-3650 days\n")
		return
	}
	now := s.now()
	token, err := s.st.createToken(p.user, req.Name, req.Scope, now.AddDate(0, 0, req.Days), now)
	if err != nil {
		text(w, http.StatusInternalServerError, "could not create the token\n")
		return
	}
	s.st.log(now, p.user, "token", fmt.Sprintf("created %q (%s, %d days)", req.Name, req.Scope, req.Days))
	text(w, http.StatusOK, token+"\n")
}

func (s *server) listTokens(w http.ResponseWriter, p *principal) {
	ts, err := s.st.tokens(p.user)
	if err != nil {
		text(w, http.StatusInternalServerError, "could not read tokens\n")
		return
	}
	var b strings.Builder
	for _, t := range ts {
		fmt.Fprintf(&b, "%d\t%s\t%s\t%d\t%d\t%d\n", t.ID, t.Name, t.Scope, t.Created, t.Expires, t.LastUsed)
	}
	text(w, http.StatusOK, b.String())
}

// ---- preferences and audit log ----

var prefKeyRE = regexp.MustCompile(`^[a-z0-9_.-]{1,32}$`)

func (s *server) getPrefs(w http.ResponseWriter) {
	m, err := s.st.prefs()
	if err != nil {
		text(w, http.StatusInternalServerError, "could not read preferences\n")
		return
	}
	var b strings.Builder
	for k, v := range m {
		fmt.Fprintf(&b, "%s=%s\n", k, v)
	}
	text(w, http.StatusOK, b.String())
}

func (s *server) setPref(w http.ResponseWriter, key, value string) {
	if !prefKeyRE.MatchString(key) || len(value) > 256 || strings.ContainsAny(value, "\r\n") {
		text(w, http.StatusBadRequest, "bad preference\n")
		return
	}
	if err := s.st.setPref(key, value); err != nil {
		text(w, http.StatusInternalServerError, "could not save\n")
		return
	}
	text(w, http.StatusOK, "saved\n")
}

func (s *server) getAudit(w http.ResponseWriter) {
	es, err := s.st.audit(50)
	if err != nil {
		text(w, http.StatusInternalServerError, "could not read the log\n")
		return
	}
	var b strings.Builder
	for _, e := range es {
		fmt.Fprintf(&b, "%d\t%s\t%s\t%s\n", e.TS, e.User, e.Action, strings.ReplaceAll(e.Detail, "\n", " "))
	}
	text(w, http.StatusOK, b.String())
}

// ---- config files and the pxmxfw command ----

func (s *server) fileFor(name string) (string, bool) {
	switch name {
	case "settings":
		return filepath.Join(s.etc, "pxmxfw.conf"), true
	case "interfaces", "services", "forwards", "hosts", "wireguard", "packages":
		return filepath.Join(s.etc, name), true
	}
	return "", false
}

func (s *server) command(args ...string) ([]byte, error) {
	return s.commandT(cmdTimeout, args...)
}

func (s *server) commandT(timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, s.pxmxfw, args...).CombinedOutput()
}

func (s *server) run(w http.ResponseWriter, args ...string) {
	out, _ := s.command(args...)
	text(w, http.StatusOK, string(out))
}

func (s *server) getFile(w http.ResponseWriter, name string) {
	f, ok := s.fileFor(name)
	if !ok {
		text(w, http.StatusBadRequest, "unknown file\n")
		return
	}
	if name == "interfaces" {
		s.mu.Lock()
		s.command("detect") // pick up NICs added since boot
		s.mu.Unlock()
	}
	b, _ := os.ReadFile(f)
	text(w, http.StatusOK, string(b))
}

func (s *server) save(w http.ResponseWriter, p *principal, name string, body []byte) {
	f, ok := s.fileFor(name)
	if !ok {
		text(w, http.StatusBadRequest, "unknown file\n")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rnd := make([]byte, 6)
	rand.Read(rnd)
	tmp := f + ".new." + hex.EncodeToString(rnd)
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		text(w, http.StatusInternalServerError, "could not write the file\n")
		return
	}
	if out, err := s.command("validate", name, tmp); err != nil {
		os.Remove(tmp)
		// report line numbers, not the temporary path
		msg := regexp.MustCompile(`(?m)^`+regexp.QuoteMeta(tmp)+`:([0-9]+):`).ReplaceAllString(string(out), "line $1:")
		msg = strings.ReplaceAll(msg, tmp+": ", "")
		text(w, http.StatusUnprocessableEntity, msg)
		return
	}
	if err := os.Rename(tmp, f); err != nil {
		os.Remove(tmp)
		text(w, http.StatusInternalServerError, "could not replace the file\n")
		return
	}
	s.st.log(s.now(), p.user, "save", name+via(p))
	text(w, http.StatusOK, "saved\n")
}

func (s *server) apply(w http.ResponseWriter, p *principal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out, err := s.command("apply")
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			out = append(out, []byte(err.Error()+"\n")...)
		}
		s.st.log(s.now(), p.user, "apply", "failed"+via(p))
		text(w, http.StatusInternalServerError, string(out))
		return
	}
	s.st.log(s.now(), p.user, "apply", "ok"+via(p))
	text(w, http.StatusOK, string(out))
}

// packages installs or removes Alpine packages through pxmxfw pkg-*.
func (s *server) packages(w http.ResponseWriter, p *principal, action, name string) {
	args := []string{action}
	if action == "pkg-add" || action == "pkg-del" {
		names := strings.Fields(name)
		if len(names) == 0 || len(names) > 20 {
			text(w, http.StatusBadRequest, "name 1-20 packages\n")
			return
		}
		args = append(args, names...)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out, err := s.commandT(pkgTimeout, args...)
	detail := strings.TrimSpace(strings.TrimPrefix(action, "pkg-") + " " + name)
	if err != nil {
		s.st.log(s.now(), p.user, "packages", detail+" failed"+via(p))
		text(w, http.StatusInternalServerError, string(out))
		return
	}
	s.st.log(s.now(), p.user, "packages", detail+via(p))
	text(w, http.StatusOK, string(out))
}

func via(p *principal) string {
	if p.viaToken() {
		return " (token)"
	}
	return ""
}

// ---- failed-attempt limiter ----

// limiter blocks a key (client address or user) after 5 failures within
// 5 minutes, until those failures age out.
type limiter struct {
	mu    sync.Mutex
	now   func() time.Time
	fails map[string][]time.Time
}

const (
	maxFails   = 5
	failWindow = 5 * time.Minute
)

func newLimiter(now func() time.Time) *limiter {
	return &limiter{now: now, fails: map[string][]time.Time{}}
}

func (l *limiter) recent(key string) []time.Time {
	cut := l.now().Add(-failWindow)
	ts := l.fails[key]
	i := 0
	for i < len(ts) && !ts[i].After(cut) {
		i++
	}
	ts = ts[i:]
	if len(ts) == 0 {
		delete(l.fails, key)
	} else {
		l.fails[key] = ts
	}
	return ts
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(key)) < maxFails
}

func (l *limiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fails[key] = append(l.recent(key), l.now())
}

func (l *limiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, key)
}
