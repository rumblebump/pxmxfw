package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// softKey is a minimal software security key: ES256, "none" attestation.
type softKey struct {
	id    []byte
	priv  *ecdsa.PrivateKey
	count uint32
	rpid  string
}

func newSoftKey(rpid string) *softKey {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 16)
	rand.Read(id)
	return &softKey{id: id, priv: priv, rpid: rpid}
}

var b64 = base64.RawURLEncoding

func (k *softKey) authData(flags byte, attested []byte) []byte {
	h := sha256.Sum256([]byte(k.rpid))
	out := append(h[:], flags)
	out = binary.BigEndian.AppendUint32(out, k.count)
	return append(out, attested...)
}

func clientData(typ, challenge, origin string) []byte {
	b, _ := json.Marshal(map[string]string{"type": typ, "challenge": challenge, "origin": origin})
	return b
}

// register answers navigator.credentials.create() options.
func (k *softKey) register(t *testing.T, options json.RawMessage, origin string) []byte {
	var o struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &o); err != nil || o.PublicKey.Challenge == "" {
		t.Fatalf("creation options: %s", options)
	}
	x, y := k.priv.PublicKey.X.FillBytes(make([]byte, 32)), k.priv.PublicKey.Y.FillBytes(make([]byte, 32))
	cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	attested := make([]byte, 16) // AAGUID
	attested = binary.BigEndian.AppendUint16(attested, uint16(len(k.id)))
	attested = append(append(attested, k.id...), cose...)
	att, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": k.authData(0x41, attested)})
	body, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(k.id), "rawId": b64.EncodeToString(k.id), "type": "public-key",
		"response": map[string]string{
			"clientDataJSON":    b64.EncodeToString(clientData("webauthn.create", o.PublicKey.Challenge, origin)),
			"attestationObject": b64.EncodeToString(att),
		},
	})
	return body
}

// sign answers navigator.credentials.get() options.
func (k *softKey) sign(t *testing.T, options json.RawMessage, origin string) json.RawMessage {
	var o struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &o); err != nil || o.PublicKey.Challenge == "" {
		t.Fatalf("request options: %s", options)
	}
	k.count++
	ad := k.authData(0x01, nil)
	cd := clientData("webauthn.get", o.PublicKey.Challenge, origin)
	h := sha256.Sum256(cd)
	sig, _ := ecdsa.SignASN1(rand.Reader, k.priv, sha256Of(append(ad, h[:]...)))
	body, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(k.id), "rawId": b64.EncodeToString(k.id), "type": "public-key",
		"response": map[string]string{
			"clientDataJSON": b64.EncodeToString(cd), "authenticatorData": b64.EncodeToString(ad),
			"signature": b64.EncodeToString(sig),
		},
	})
	return body
}

func sha256Of(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

// doHost is env.do with a Host header.
func (e *env) doHost(host string, r req) *httptest.ResponseRecorder {
	hr := httptest.NewRequest(r.method, "https://"+host+"/api?"+r.query, strings.NewReader(r.body))
	hr.RemoteAddr = "192.0.2.1:1234"
	if r.method == "POST" && !r.noHeader {
		hr.Header.Set("X-Pxmxfw", "1")
	}
	if r.cookie != "" {
		hr.AddCookie(&http.Cookie{Name: cookieName, Value: r.cookie})
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, hr)
	return w
}

type flowJSON struct {
	Flow    string          `json:"flow"`
	Options json.RawMessage `json:"options"`
	Need    []string        `json:"need"`
}

func TestSecurityKeys(t *testing.T) {
	const host, origin = "fw.lan:8443", "https://fw.lan:8443"
	e := newEnv(t)
	key := newSoftKey("fw.lan")
	login := func(body string) *httptest.ResponseRecorder {
		return e.doHost(host, req{method: "POST", query: "action=login", body: body})
	}
	cookieOf := func(w *httptest.ResponseRecorder) string {
		for _, c := range w.Result().Cookies() {
			if c.Name == cookieName {
				return c.Value
			}
		}
		t.Fatalf("no cookie: %d %q", w.Code, w.Body.String())
		return ""
	}
	c := cookieOf(login(`{"user":"root","password":"pw"}`))

	// adding a key needs a confirmed session
	e.expect(e.doHost(host, req{method: "POST", query: "action=key-register-begin", body: `{"name":"yubikey"}`, cookie: c}), 403, "register without confirming")
	e.expect(e.doHost(host, req{method: "POST", query: "action=stepup", body: `{"password":"pw"}`, cookie: c}), 200, "confirm")
	// not by IP address
	e.expect(e.doHost("192.0.2.10:8443", req{method: "POST", query: "action=key-register-begin", body: `{"name":"yubikey"}`, cookie: c}), 400, "register by IP")

	w := e.doHost(host, req{method: "POST", query: "action=key-register-begin", body: `{"name":"yubikey"}`, cookie: c})
	e.expect(w, 200, "register begin")
	var fr flowJSON
	json.Unmarshal(w.Body.Bytes(), &fr)
	e.expect(e.doHost(host, req{method: "POST", query: "action=key-register-finish&name=" + fr.Flow,
		body: string(newSoftKey("fw.lan").register(t, fr.Options, "https://evil.example")), cookie: c}), 400, "wrong origin")
	// a flow is used up by any answer, so start again
	w = e.doHost(host, req{method: "POST", query: "action=key-register-begin", body: `{"name":"yubikey"}`, cookie: c})
	json.Unmarshal(w.Body.Bytes(), &fr)
	e.expect(e.doHost(host, req{method: "POST", query: "action=key-register-finish&name=" + fr.Flow,
		body: string(key.register(t, fr.Options, origin)), cookie: c}), 200, "register finish")
	if w := e.doHost(host, req{method: "GET", query: "action=keys", cookie: c}); !strings.Contains(w.Body.String(), "\tyubikey\t") {
		t.Fatalf("keys: %q", w.Body.String())
	}

	// login now asks for the key
	w = login(`{"user":"root","password":"pw"}`)
	json.Unmarshal(w.Body.Bytes(), &fr)
	if w.Code != 401 || w.Header().Get("X-Pxmxfw-Need") != "webauthn" || fr.Flow == "" {
		t.Fatalf("login without key: %d %v %q", w.Code, w.Header(), w.Body.String())
	}
	// an answer signed by another key is refused
	other := newSoftKey("fw.lan")
	other.id = key.id
	bad, _ := json.Marshal(map[string]any{"user": "root", "password": "pw", "flow": fr.Flow, "assertion": other.sign(t, fr.Options, origin)})
	e.expect(login(string(bad)), 401, "wrong key")

	w = login(`{"user":"root","password":"pw"}`)
	json.Unmarshal(w.Body.Bytes(), &fr)
	good, _ := json.Marshal(map[string]any{"user": "root", "password": "pw", "flow": fr.Flow, "assertion": key.sign(t, fr.Options, origin)})
	c = cookieOf(login(string(good)))
	e.expect(login(string(good)), 401, "replayed flow")
	// the key login confirms changes for a while
	e.expect(e.doHost(host, req{method: "POST", query: "action=apply", cookie: c}), 200, "apply after key login")

	// confirming with the key
	e.now = e.now.Add(stepUpWindow + 1)
	w = e.doHost(host, req{method: "POST", query: "action=apply", cookie: c})
	if w.Code != 403 || w.Header().Get("X-Pxmxfw-Stepup") != "webauthn" {
		t.Fatalf("expected key step-up: %d %v", w.Code, w.Header())
	}
	e.expect(e.doHost(host, req{method: "POST", query: "action=stepup", body: `{"password":"pw"}`, cookie: c}), 403, "password is not enough with a key")
	w = e.doHost(host, req{method: "POST", query: "action=stepup-begin", body: "", cookie: c})
	json.Unmarshal(w.Body.Bytes(), &fr)
	su, _ := json.Marshal(map[string]any{"flow": fr.Flow, "assertion": key.sign(t, fr.Options, origin)})
	e.expect(e.doHost(host, req{method: "POST", query: "action=stepup", body: string(su), cookie: c}), 200, "confirm with key")
	e.expect(e.doHost(host, req{method: "POST", query: "action=apply", cookie: c}), 200, "apply after key confirm")

	// a cloned key (counter going backwards) is refused
	e.now = e.now.Add(stepUpWindow + 1)
	w = e.doHost(host, req{method: "POST", query: "action=stepup-begin", body: "", cookie: c})
	json.Unmarshal(w.Body.Bytes(), &fr)
	key.count = 0
	su, _ = json.Marshal(map[string]any{"flow": fr.Flow, "assertion": key.sign(t, fr.Options, origin)})
	e.expect(e.doHost(host, req{method: "POST", query: "action=stepup", body: string(su), cookie: c}), 403, "cloned key")

	// keys are per host name: by another name, the password confirms again
	w = e.doHost("other.lan:8443", req{method: "POST", query: "action=apply", cookie: c})
	if w.Header().Get("X-Pxmxfw-Stepup") != "password" {
		t.Fatalf("other host: %v", w.Header())
	}
}
