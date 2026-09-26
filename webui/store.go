package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// store keeps the web UI's own state in SQLite: login sessions, UI
// preferences and a log of changes. The firewall configuration itself stays
// in the /etc/pxmxfw files.
type store struct{ db *sql.DB }

const schema = `
CREATE TABLE IF NOT EXISTS sessions (
	token_hash TEXT PRIMARY KEY,
	user       TEXT NOT NULL,
	created    INTEGER NOT NULL,
	seen       INTEGER NOT NULL,
	stepup_until INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS prefs (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
	ts     INTEGER NOT NULL,
	user   TEXT NOT NULL,
	action TEXT NOT NULL,
	detail TEXT NOT NULL
);
`

func openStore(path string) (*store, error) {
	db, err := sql.Open("sqlite3", "file:"+path+"?_busy_timeout=5000&_journal_mode=WAL")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema + schemaAuth + schemaWebAuthn); err != nil {
		db.Close()
		return nil, err
	}
	return &store{db}, nil
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// newSession returns a random token; only its hash is stored.
func (s *store) newSession(user string, now time.Time) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	_, err := s.db.Exec(`INSERT INTO sessions (token_hash, user, created, seen) VALUES (?, ?, ?, ?)`,
		hashToken(token), user, now.Unix(), now.Unix())
	return token, err
}

// session returns the user of a live session and refreshes its idle timer.
func (s *store) session(token string, now time.Time) (string, bool) {
	if token == "" {
		return "", false
	}
	var user string
	err := s.db.QueryRow(`UPDATE sessions SET seen = ? WHERE token_hash = ? AND seen > ? AND created > ? RETURNING user`,
		now.Unix(), hashToken(token), now.Add(-idleTimeout).Unix(), now.Add(-maxSessionAge).Unix()).Scan(&user)
	return user, err == nil
}

func (s *store) endSession(token string) {
	s.db.Exec(`DELETE FROM sessions WHERE token_hash = ?`, hashToken(token))
}

func (s *store) prune(now time.Time) {
	s.db.Exec(`DELETE FROM sessions WHERE seen <= ? OR created <= ?`,
		now.Add(-idleTimeout).Unix(), now.Add(-maxSessionAge).Unix())
	s.db.Exec(`DELETE FROM audit WHERE ts < ?`, now.AddDate(0, 0, -90).Unix())
}

func (s *store) prefs() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT key, value FROM prefs ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

func (s *store) setPref(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO prefs (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

func (s *store) log(now time.Time, user, action, detail string) {
	s.db.Exec(`INSERT INTO audit (ts, user, action, detail) VALUES (?, ?, ?, ?)`,
		now.Unix(), user, action, detail)
}

type auditEntry struct {
	TS                   int64
	User, Action, Detail string
}

func (s *store) audit(limit int) ([]auditEntry, error) {
	rows, err := s.db.Query(`SELECT ts, user, action, detail FROM audit ORDER BY ts DESC, rowid DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []auditEntry
	for rows.Next() {
		var e auditEntry
		if err := rows.Scan(&e.TS, &e.User, &e.Action, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

const schemaAuth = `
CREATE TABLE IF NOT EXISTS totp (
	user      TEXT PRIMARY KEY,
	secret    TEXT NOT NULL,
	enabled   INTEGER NOT NULL DEFAULT 0,
	last_step INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS tokens (
	id         INTEGER PRIMARY KEY,
	user       TEXT NOT NULL,
	name       TEXT NOT NULL,
	scope      TEXT NOT NULL,
	token_hash TEXT NOT NULL UNIQUE,
	created    INTEGER NOT NULL,
	expires    INTEGER NOT NULL,
	last_used  INTEGER NOT NULL DEFAULT 0
);
`

// ---- TOTP ----

// totpSecret returns the user's secret and whether it is switched on.
func (s *store) totpSecret(user string) (secret string, enabled bool) {
	s.db.QueryRow(`SELECT secret, enabled FROM totp WHERE user = ?`, user).Scan(&secret, &enabled)
	return
}

// setPendingTOTP stores a new secret that only takes effect once confirmed.
func (s *store) setPendingTOTP(user, secret string) error {
	_, err := s.db.Exec(`INSERT INTO totp (user, secret, enabled) VALUES (?, ?, 0)
		ON CONFLICT(user) DO UPDATE SET secret = excluded.secret, enabled = 0, last_step = 0
		WHERE totp.enabled = 0`, user, secret)
	return err
}

func (s *store) enableTOTP(user string) error {
	_, err := s.db.Exec(`UPDATE totp SET enabled = 1 WHERE user = ?`, user)
	return err
}

func (s *store) deleteTOTP(user string) error {
	_, err := s.db.Exec(`DELETE FROM totp WHERE user = ?`, user)
	return err
}

// useTOTPStep records a used code so it cannot be replayed. It fails when
// the step (or a later one) was already used.
func (s *store) useTOTPStep(user string, step int64) bool {
	res, err := s.db.Exec(`UPDATE totp SET last_step = ? WHERE user = ? AND last_step < ?`, step, user, step)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n == 1
}

// ---- personal access tokens ----

type apiToken struct {
	ID                         int64
	Name, Scope                string
	Created, Expires, LastUsed int64
}

func (s *store) createToken(user, name, scope string, expires, now time.Time) (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := "pxm_" + hex.EncodeToString(b)
	_, err := s.db.Exec(`INSERT INTO tokens (user, name, scope, token_hash, created, expires) VALUES (?, ?, ?, ?, ?, ?)`,
		user, name, scope, hashToken(token), now.Unix(), expires.Unix())
	return token, err
}

// tokenUser returns the owner and scope of a valid token.
func (s *store) tokenUser(token string, now time.Time) (user, scope string, ok bool) {
	err := s.db.QueryRow(`UPDATE tokens SET last_used = ? WHERE token_hash = ? AND expires > ? RETURNING user, scope`,
		now.Unix(), hashToken(token), now.Unix()).Scan(&user, &scope)
	return user, scope, err == nil
}

func (s *store) tokens(user string) ([]apiToken, error) {
	rows, err := s.db.Query(`SELECT id, name, scope, created, expires, last_used FROM tokens WHERE user = ? ORDER BY id`, user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []apiToken
	for rows.Next() {
		var t apiToken
		if err := rows.Scan(&t.ID, &t.Name, &t.Scope, &t.Created, &t.Expires, &t.LastUsed); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *store) deleteToken(user string, id int64) bool {
	res, err := s.db.Exec(`DELETE FROM tokens WHERE id = ? AND user = ?`, id, user)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n == 1
}

// ---- step-up ----

func (s *store) setStepUp(token string, until time.Time) {
	s.db.Exec(`UPDATE sessions SET stepup_until = ? WHERE token_hash = ?`, until.Unix(), hashToken(token))
}

func (s *store) steppedUp(token string, now time.Time) bool {
	var until int64
	s.db.QueryRow(`SELECT stepup_until FROM sessions WHERE token_hash = ?`, hashToken(token)).Scan(&until)
	return until > now.Unix()
}
