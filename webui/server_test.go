package main

import (
	"encoding/base32"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeAuth map[string]string

func (f fakeAuth) Authenticate(u, p string) error {
	if pw, ok := f[u]; ok && pw == p {
		return nil
	}
	return os.ErrPermission
}

type env struct {
	t   *testing.T
	s   *server
	h   http.Handler
	now time.Time
	etc string
}

// A stand-in for the pxmxfw command: validate rejects bodies containing "bad".
const fakePxmxfw = `#!/bin/sh
case $1 in
	validate) if grep -q bad "$3"; then echo "$3:2: bad value"; exit 1; fi ;;
	apply) echo applied ;;
	status) echo firewall=active; echo "addr=eth0 10.20.0.5/24"; echo "addr=eth0 fd00::5/64" ;;
	detect) ;;
	wg-keypair) echo private=PRIV; echo public=PUB ;;
	pkg-list) echo "nano 8.4-r0" ;;
	pkg-search) [ "$2" = nano ] || { echo "bad name"; exit 1; }; echo "nano-8.4-r0 - editor" ;;
	pkg-add|pkg-del) shift; echo "done: $*" ;;
	pkg-sync|pkg-upgrade) echo ok ;;
	*) exit 1 ;;
esac
`

func newEnv(t *testing.T) *env {
	failDelay = 0
	dir := t.TempDir()
	cmd := filepath.Join(dir, "pxmxfw")
	os.WriteFile(cmd, []byte(fakePxmxfw), 0o755)
	etc := filepath.Join(dir, "etc")
	os.Mkdir(etc, 0o755)
	os.WriteFile(filepath.Join(etc, "services"), []byte("tcp 22\n"), 0o644)
	st, err := openStore(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, now: time.Unix(1_800_000_000, 0), etc: etc}
	e.s = &server{
		st: st, auth: fakeAuth{"root": "pw", "bob": "bobpw"},
		allowed: func(u string) bool { return u == "root" },
		pxmxfw:  cmd, etc: etc, leases: filepath.Join(dir, "leases"), www: dir, host: "fw",
		now: func() time.Time { return e.now }, limit: newLimiter(func() time.Time { return e.now }),
	}
	e.h = e.s.routes()
	return e
}

type req struct {
	method, query, body, cookie, bearer string
	noHeader                            bool
}

func (e *env) do(r req) *httptest.ResponseRecorder {
	hr := httptest.NewRequest(r.method, "/api?"+r.query, strings.NewReader(r.body))
	hr.RemoteAddr = "192.0.2.1:1234"
	if r.method == "POST" && !r.noHeader {
		hr.Header.Set("X-Pxmxfw", "1")
	}
	if r.cookie != "" {
		hr.AddCookie(&http.Cookie{Name: cookieName, Value: r.cookie})
	}
	if r.bearer != "" {
		hr.Header.Set("Authorization", "Bearer "+r.bearer)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, hr)
	return w
}

func (e *env) expect(w *httptest.ResponseRecorder, code int, what string) {
	e.t.Helper()
	if w.Code != code {
		e.t.Fatalf("%s: got %d %q, want %d", what, w.Code, w.Body.String(), code)
	}
}

func (e *env) login(user, pw, code string) string {
	e.t.Helper()
	w := e.do(req{method: "POST", query: "action=login", body: `{"user":"` + user + `","password":"` + pw + `","code":"` + code + `"}`})
	e.expect(w, 200, "login")
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
				e.t.Fatalf("cookie flags: %+v", c)
			}
			return c.Value
		}
	}
	e.t.Fatal("no session cookie")
	return ""
}

func (e *env) code(secret string) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	return hotp(key, uint64(e.now.Unix()/totpStep))
}

func TestLoginAndSessions(t *testing.T) {
	e := newEnv(t)
	e.expect(e.do(req{method: "GET", query: "action=status"}), 401, "no session")
	e.expect(e.do(req{method: "POST", query: "action=login", body: `{"user":"root","password":"pw"}`, noHeader: true}), 403, "login without X-Pxmxfw")
	e.expect(e.do(req{method: "POST", query: "action=login", body: `{"user":"root","password":"nope"}`}), 401, "wrong password")
	e.expect(e.do(req{method: "POST", query: "action=login", body: `{"user":"bob","password":"bobpw"}`}), 401, "user not in group")
	c := e.login("root", "pw", "")
	if w := e.do(req{method: "GET", query: "action=status", cookie: c}); w.Code != 200 || !strings.Contains(w.Body.String(), "firewall=active") {
		t.Fatalf("status: %d %q", w.Code, w.Body.String())
	}
	e.expect(e.do(req{method: "GET", query: "action=status", cookie: "forged"}), 401, "forged cookie")
	e.expect(e.do(req{method: "GET", query: "action=file&name=../../etc/shadow", cookie: c}), 400, "unknown file")

	e.now = e.now.Add(idleTimeout + time.Second)
	e.expect(e.do(req{method: "GET", query: "action=status", cookie: c}), 401, "idle session")

	c = e.login("root", "pw", "")
	e.expect(e.do(req{method: "POST", query: "action=logout", cookie: c}), 200, "logout")
	e.expect(e.do(req{method: "GET", query: "action=status", cookie: c}), 401, "after logout")
}

func TestLoginLimiter(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < maxFails; i++ {
		e.expect(e.do(req{method: "POST", query: "action=login", body: `{"user":"root","password":"x"}`}), 401, "wrong password")
	}
	e.expect(e.do(req{method: "POST", query: "action=login", body: `{"user":"root","password":"pw"}`}), 429, "locked out")
	e.now = e.now.Add(failWindow + time.Second)
	e.login("root", "pw", "")
}

func TestChangesNeedConfirmation(t *testing.T) {
	e := newEnv(t)
	c := e.login("root", "pw", "")
	w := e.do(req{method: "POST", query: "action=save&name=services", body: "tcp 80\n", cookie: c})
	e.expect(w, 403, "save without confirming")
	if w.Header().Get("X-Pxmxfw-Stepup") != "password" {
		t.Fatalf("step-up method: %q", w.Header().Get("X-Pxmxfw-Stepup"))
	}
	e.expect(e.do(req{method: "POST", query: "action=save&name=services", body: "x", cookie: c, noHeader: true}), 403, "save without X-Pxmxfw")
	e.expect(e.do(req{method: "POST", query: "action=stepup", body: `{"password":"wrong"}`, cookie: c}), 403, "wrong password")
	e.expect(e.do(req{method: "POST", query: "action=stepup", body: `{"password":"pw"}`, cookie: c}), 200, "confirm")
	e.expect(e.do(req{method: "POST", query: "action=save&name=services", body: "tcp 80\n", cookie: c}), 200, "save")
	if b, _ := os.ReadFile(filepath.Join(e.etc, "services")); string(b) != "tcp 80\n" {
		t.Fatalf("services = %q", b)
	}
	w = e.do(req{method: "POST", query: "action=save&name=services", body: "tcp 80\nbad\n", cookie: c})
	e.expect(w, 422, "invalid file")
	if got := w.Body.String(); got != "line 2: bad value\n" {
		t.Fatalf("validation message %q", got)
	}
	if b, _ := os.ReadFile(filepath.Join(e.etc, "services")); string(b) != "tcp 80\n" {
		t.Fatalf("invalid save changed the file: %q", b)
	}
	e.expect(e.do(req{method: "POST", query: "action=apply", cookie: c}), 200, "apply")
	e.now = e.now.Add(stepUpWindow + time.Second)
	e.expect(e.do(req{method: "POST", query: "action=apply", cookie: c}), 403, "confirmation expired")
	if w := e.do(req{method: "GET", query: "action=audit", cookie: c}); !strings.Contains(w.Body.String(), "\tsave\tservices") {
		t.Fatalf("audit log: %q", w.Body.String())
	}
}

func TestTOTP(t *testing.T) {
	e := newEnv(t)
	c := e.login("root", "pw", "")
	w := e.do(req{method: "POST", query: "action=totp-setup", cookie: c})
	e.expect(w, 200, "totp setup")
	secret := parseKV(w.Body.String())["secret"]
	if !strings.HasPrefix(parseKV(w.Body.String())["uri"], "otpauth://totp/") {
		t.Fatalf("setup: %q", w.Body.String())
	}
	e.expect(e.do(req{method: "POST", query: "action=totp-enable", body: `{"code":"000000"}`, cookie: c}), 400, "wrong code")
	e.expect(e.do(req{method: "POST", query: "action=totp-enable", body: `{"code":"` + e.code(secret) + `"}`, cookie: c}), 200, "enable")
	e.expect(e.do(req{method: "POST", query: "action=totp-setup", cookie: c}), 409, "setup again while on")

	// login now needs the code, and a code works only once
	e.now = e.now.Add(totpStep * time.Second)
	w = e.do(req{method: "POST", query: "action=login", body: `{"user":"root","password":"pw"}`})
	if w.Code != 401 || w.Header().Get("X-Pxmxfw-Need") != "totp" {
		t.Fatalf("login without code: %d %v", w.Code, w.Header())
	}
	code := e.code(secret)
	c = e.login("root", "pw", code)
	e.expect(e.do(req{method: "POST", query: "action=login", body: `{"user":"root","password":"pw","code":"` + code + `"}`}), 401, "replayed code")
	// the login code counts as confirmation for a few minutes
	e.expect(e.do(req{method: "POST", query: "action=apply", cookie: c}), 200, "apply after TOTP login")
	e.now = e.now.Add(stepUpWindow + time.Second)
	w = e.do(req{method: "POST", query: "action=apply", cookie: c})
	if w.Code != 403 || w.Header().Get("X-Pxmxfw-Stepup") != "totp" {
		t.Fatalf("expected totp step-up, got %d %v", w.Code, w.Header())
	}
	e.expect(e.do(req{method: "POST", query: "action=stepup", body: `{"password":"pw"}`, cookie: c}), 403, "password is not enough with TOTP on")
	e.expect(e.do(req{method: "POST", query: "action=stepup", body: `{"code":"` + e.code(secret) + `"}`, cookie: c}), 200, "confirm with code")
	e.expect(e.do(req{method: "POST", query: "action=totp-disable", cookie: c}), 200, "disable")
}

func TestAccessTokens(t *testing.T) {
	e := newEnv(t)
	c := e.login("root", "pw", "")
	create := func(scope string) string {
		w := e.do(req{method: "POST", query: "action=token-create", body: `{"name":"ansible","scope":"` + scope + `","days":30}`, cookie: c})
		e.expect(w, 200, "create token")
		return strings.TrimSpace(w.Body.String())
	}
	e.expect(e.do(req{method: "POST", query: "action=token-create", body: `{"name":"x","scope":"read","days":1}`, cookie: c}), 403, "create without confirming")
	e.do(req{method: "POST", query: "action=stepup", body: `{"password":"pw"}`, cookie: c})
	ro, rw := create("read"), create("write")

	e.expect(e.do(req{method: "GET", query: "action=file&name=services", bearer: ro}), 200, "read with token")
	e.expect(e.do(req{method: "POST", query: "action=save&name=services", body: "tcp 1\n", bearer: ro, noHeader: true}), 403, "save with read token")
	e.expect(e.do(req{method: "POST", query: "action=save&name=services", body: "tcp 1\n", bearer: rw, noHeader: true}), 200, "save with write token")
	e.expect(e.do(req{method: "GET", query: "action=tokens", bearer: rw}), 403, "token management with a token")
	e.expect(e.do(req{method: "GET", query: "action=status", bearer: "pxm_forged"}), 401, "forged token")

	w := e.do(req{method: "GET", query: "action=tokens", cookie: c})
	if n := strings.Count(w.Body.String(), "\n"); n != 2 {
		t.Fatalf("tokens: %q", w.Body.String())
	}
	id := strings.SplitN(w.Body.String(), "\t", 2)[0]
	e.expect(e.do(req{method: "POST", query: "action=token-delete&name=" + id, cookie: c}), 200, "delete token")
	e.expect(e.do(req{method: "GET", query: "action=status", bearer: ro}), 401, "deleted token")
	e.now = e.now.AddDate(0, 0, 31)
	e.expect(e.do(req{method: "GET", query: "action=status", bearer: rw}), 401, "expired token")
}

func TestPackages(t *testing.T) {
	e := newEnv(t)
	c := e.login("root", "pw", "")
	if w := e.do(req{method: "GET", query: "action=pkgs", cookie: c}); w.Body.String() != "nano 8.4-r0\n" {
		t.Fatalf("pkgs: %q", w.Body.String())
	}
	e.expect(e.do(req{method: "GET", query: "action=pkg-search&name=nano", cookie: c}), 200, "search")
	e.expect(e.do(req{method: "GET", query: "action=pkg-search&name=x", cookie: c}), 400, "bad search")
	e.expect(e.do(req{method: "POST", query: "action=pkg-add&name=nano", cookie: c}), 403, "install without confirming")
	e.do(req{method: "POST", query: "action=stepup", body: `{"password":"pw"}`, cookie: c})
	w := e.do(req{method: "POST", query: "action=pkg-add&name=nano%20htop", cookie: c})
	if w.Code != 200 || w.Body.String() != "done: nano htop\n" {
		t.Fatalf("pkg-add: %d %q", w.Code, w.Body.String())
	}
	e.expect(e.do(req{method: "POST", query: "action=pkg-del&name=", cookie: c}), 400, "remove nothing")
	e.expect(e.do(req{method: "POST", query: "action=pkg-upgrade", cookie: c}), 200, "upgrade")
	if w := e.do(req{method: "GET", query: "action=audit", cookie: c}); !strings.Contains(w.Body.String(), "\tpackages\tadd nano htop") {
		t.Fatalf("audit: %q", w.Body.String())
	}
}

func TestPrefsAndHeaders(t *testing.T) {
	e := newEnv(t)
	c := e.login("root", "pw", "")
	e.expect(e.do(req{method: "POST", query: "action=pref&name=ctid", body: "105", cookie: c}), 200, "set pref")
	if w := e.do(req{method: "POST", query: "action=wgkeypair", cookie: c}); w.Code != 200 || !strings.Contains(w.Body.String(), "public=PUB") {
		t.Fatalf("wgkeypair: %d %q", w.Code, w.Body.String())
	}
	e.expect(e.do(req{method: "GET", query: "action=file&name=wireguard", cookie: c}), 200, "wireguard file")
	e.expect(e.do(req{method: "POST", query: "action=pref&name=BAD%20KEY", body: "1", cookie: c}), 400, "bad pref key")
	w := e.do(req{method: "GET", query: "action=prefs", cookie: c})
	if parseKV(w.Body.String())["ctid"] != "105" {
		t.Fatalf("prefs: %q", w.Body.String())
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatal("missing CSP")
	}
}

func parseKV(s string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			m[k] = v
		}
	}
	return m
}

func TestTOTPVectors(t *testing.T) {
	// RFC 6238 appendix B, SHA-1 secret, truncated to 6 digits
	key := []byte("12345678901234567890")
	for ts, want := range map[int64]string{59: "287082", 1111111109: "081804", 2000000000: "279037"} {
		if got := hotp(key, uint64(ts/totpStep)); got != want {
			t.Errorf("T=%d: %s, want %s", ts, got, want)
		}
	}
}
