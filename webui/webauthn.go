package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Security keys (Nitrokey, YubiKey, ...) through WebAuthn, as a second
// factor at login and to confirm changes. Browsers only allow WebAuthn on
// a host name with a certificate they trust, so the relying party ID is the
// host name the UI was opened with, and keys only work under that name.

const flowTimeout = 2 * time.Minute

const schemaWebAuthn = `
CREATE TABLE IF NOT EXISTS webauthn_keys (
	id        TEXT PRIMARY KEY,
	user      TEXT NOT NULL,
	rpid      TEXT NOT NULL,
	name      TEXT NOT NULL,
	data      TEXT NOT NULL,
	created   INTEGER NOT NULL,
	last_used INTEGER NOT NULL DEFAULT 0
);
`

// rpFor returns the WebAuthn settings for the host name of a request.
func rpFor(r *http.Request) (*webauthn.WebAuthn, string, error) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || net.ParseIP(strings.Trim(host, "[]")) != nil {
		return nil, "", fmt.Errorf("security keys need the UI opened by host name (like https://fw.lan:8443), not by IP address")
	}
	w, err := webauthn.New(&webauthn.Config{
		RPID:          host,
		RPDisplayName: "pxmxfw",
		RPOrigins:     []string{"https://" + r.Host},
	})
	return w, host, err
}

// waUser adapts a login to the webauthn library.
type waUser struct {
	name  string
	creds []webauthn.Credential
}

func (u *waUser) WebAuthnID() []byte {
	h := sha256.Sum256([]byte("pxmxfw user " + u.name))
	return h[:]
}
func (u *waUser) WebAuthnName() string                       { return u.name }
func (u *waUser) WebAuthnDisplayName() string                { return u.name }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// ---- storage ----

type keyInfo struct {
	ID, Name          string
	Created, LastUsed int64
}

func (s *store) keyCount(user, rpid string) int {
	var n int
	s.db.QueryRow(`SELECT count(*) FROM webauthn_keys WHERE user = ? AND rpid = ?`, user, rpid).Scan(&n)
	return n
}

func (s *store) waUser(user, rpid string) *waUser {
	u := &waUser{name: user}
	rows, err := s.db.Query(`SELECT data FROM webauthn_keys WHERE user = ? AND rpid = ?`, user, rpid)
	if err != nil {
		return u
	}
	defer rows.Close()
	for rows.Next() {
		var data string
		var c webauthn.Credential
		if rows.Scan(&data) == nil && json.Unmarshal([]byte(data), &c) == nil {
			u.creds = append(u.creds, c)
		}
	}
	return u
}

func (s *store) addKey(user, rpid, name string, c *webauthn.Credential, now time.Time) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO webauthn_keys (id, user, rpid, name, data, created) VALUES (?, ?, ?, ?, ?, ?)`,
		base64.RawURLEncoding.EncodeToString(c.ID), user, rpid, name, string(data), now.Unix())
	return err
}

// usedKey stores the new signature counter after a login or confirmation.
func (s *store) usedKey(c *webauthn.Credential, now time.Time) {
	data, _ := json.Marshal(c)
	s.db.Exec(`UPDATE webauthn_keys SET data = ?, last_used = ? WHERE id = ?`,
		string(data), now.Unix(), base64.RawURLEncoding.EncodeToString(c.ID))
}

func (s *store) keys(user, rpid string) ([]keyInfo, error) {
	rows, err := s.db.Query(`SELECT id, name, created, last_used FROM webauthn_keys WHERE user = ? AND rpid = ? ORDER BY created`, user, rpid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []keyInfo
	for rows.Next() {
		var k keyInfo
		if err := rows.Scan(&k.ID, &k.Name, &k.Created, &k.LastUsed); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *store) deleteKey(user, id string) bool {
	res, err := s.db.Exec(`DELETE FROM webauthn_keys WHERE id = ? AND user = ?`, id, user)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n == 1
}

// ---- pending ceremonies ----

// flow is a WebAuthn challenge waiting for the browser's answer. Each one
// can be used once and only by what started it (a user, and for
// registration and confirmation also the session).
type flow struct {
	kind, user, session, rpid, name string
	data                            *webauthn.SessionData
	expires                         time.Time
}

type flowStore struct {
	mu sync.Mutex
	m  map[string]flow
}

func (f *flowStore) put(fl flow) string {
	b := make([]byte, 16)
	rand.Read(b)
	id := hex.EncodeToString(b)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.m == nil {
		f.m = map[string]flow{}
	}
	for k, v := range f.m {
		if time.Now().After(v.expires) {
			delete(f.m, k)
		}
	}
	f.m[id] = fl
	return id
}

// take removes and returns a flow if it matches.
func (f *flowStore) take(id, kind, user, session, rpid string, now time.Time) (flow, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fl, ok := f.m[id]
	if !ok {
		return flow{}, false
	}
	delete(f.m, id)
	if fl.kind != kind || fl.user != user || fl.session != session || fl.rpid != rpid || now.After(fl.expires) {
		return flow{}, false
	}
	return fl, true
}

type flowReply struct {
	Flow    string `json:"flow"`
	Options any    `json:"options"`
}

func jsonReply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// beginAssertion starts a key login or confirmation for user.
func (s *server) beginAssertion(r *http.Request, kind, user, session string) (*flowReply, error) {
	wa, rpid, err := rpFor(r)
	if err != nil {
		return nil, err
	}
	u := s.st.waUser(user, rpid)
	if len(u.creds) == 0 {
		return nil, fmt.Errorf("no security key registered for %s", rpid)
	}
	opts, data, err := wa.BeginLogin(u, webauthn.WithUserVerification(protocol.VerificationDiscouraged))
	if err != nil {
		return nil, err
	}
	id := s.flows.put(flow{kind: kind, user: user, session: session, rpid: rpid, data: data, expires: s.now().Add(flowTimeout)})
	return &flowReply{Flow: id, Options: opts}, nil
}

// finishAssertion checks a browser's answer to beginAssertion.
func (s *server) finishAssertion(r *http.Request, kind, user, session, flowID string, assertion json.RawMessage) error {
	wa, rpid, err := rpFor(r)
	if err != nil {
		return err
	}
	fl, ok := s.flows.take(flowID, kind, user, session, rpid, s.now())
	if !ok {
		return fmt.Errorf("the security key request expired, try again")
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(assertion)
	if err != nil {
		return fmt.Errorf("bad security key response")
	}
	cred, err := wa.ValidateLogin(s.st.waUser(user, rpid), *fl.data, parsed)
	if err != nil {
		return fmt.Errorf("security key not accepted")
	}
	if cred.Authenticator.CloneWarning {
		return fmt.Errorf("security key refused: its counter went backwards, it may be cloned")
	}
	s.st.usedKey(cred, s.now())
	return nil
}

// ---- API actions ----

var keyNameRE = tokenNameRE

func (s *server) keyRegisterBegin(w http.ResponseWriter, r *http.Request, p *principal, body []byte) {
	var req struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &req) != nil || !keyNameRE.MatchString(req.Name) {
		text(w, http.StatusBadRequest, "give the key a name (letters, digits, space . _ -)\n")
		return
	}
	wa, rpid, err := rpFor(r)
	if err != nil {
		text(w, http.StatusBadRequest, err.Error()+"\n")
		return
	}
	u := s.st.waUser(p.user, rpid)
	opts, data, err := wa.BeginRegistration(u,
		webauthn.WithExclusions(webauthn.Credentials(u.creds).CredentialDescriptors()),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementDiscouraged,
			UserVerification: protocol.VerificationDiscouraged,
		}))
	if err != nil {
		text(w, http.StatusInternalServerError, "could not start the registration\n")
		return
	}
	id := s.flows.put(flow{kind: "register", user: p.user, session: p.session, rpid: rpid, name: req.Name, data: data, expires: s.now().Add(flowTimeout)})
	jsonReply(w, http.StatusOK, flowReply{Flow: id, Options: opts})
}

func (s *server) keyRegisterFinish(w http.ResponseWriter, r *http.Request, p *principal, flowID string, body []byte) {
	wa, rpid, err := rpFor(r)
	if err != nil {
		text(w, http.StatusBadRequest, err.Error()+"\n")
		return
	}
	fl, ok := s.flows.take(flowID, "register", p.user, p.session, rpid, s.now())
	if !ok {
		text(w, http.StatusBadRequest, "the registration expired, try again\n")
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		text(w, http.StatusBadRequest, "bad security key response\n")
		return
	}
	cred, err := wa.CreateCredential(s.st.waUser(p.user, rpid), *fl.data, parsed)
	if err != nil {
		text(w, http.StatusBadRequest, "security key not accepted: "+err.Error()+"\n")
		return
	}
	if err := s.st.addKey(p.user, rpid, fl.name, cred, s.now()); err != nil {
		text(w, http.StatusConflict, "this key is already registered\n")
		return
	}
	s.st.log(s.now(), p.user, "key", fmt.Sprintf("added %q for %s", fl.name, rpid))
	text(w, http.StatusOK, "security key added\n")
}

func (s *server) listKeys(w http.ResponseWriter, r *http.Request, p *principal) {
	_, rpid, err := rpFor(r)
	var b strings.Builder
	if err != nil {
		fmt.Fprintf(&b, "# %s\n", err)
	} else {
		ks, err := s.st.keys(p.user, rpid)
		if err != nil {
			text(w, http.StatusInternalServerError, "could not read keys\n")
			return
		}
		for _, k := range ks {
			fmt.Fprintf(&b, "%s\t%s\t%d\t%d\n", k.ID, k.Name, k.Created, k.LastUsed)
		}
	}
	text(w, http.StatusOK, b.String())
}
