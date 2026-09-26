package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP as in RFC 6238 with the defaults every authenticator app uses:
// SHA-1, 6 digits, 30 second steps.

const totpStep = 30

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func newTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

func totpURI(secret, user, host string) string {
	label := url.PathEscape("pxmxfw " + host + ":" + user)
	q := url.Values{"secret": {secret}, "issuer": {"pxmxfw " + host}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

func hotp(key []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000)
}

// totpMatch returns the time step the code is valid for, allowing one step
// of clock drift either way.
func totpMatch(secret, code string, now time.Time) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != 6 {
		return 0, false
	}
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return 0, false
	}
	step := now.Unix() / totpStep
	for _, s := range []int64{step, step - 1, step + 1} {
		if hmac.Equal([]byte(hotp(key, uint64(s))), []byte(code)) {
			return s, true
		}
	}
	return 0, false
}
