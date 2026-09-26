//go:build !cgo || nopam

package main

import "errors"

// Built without PAM (only for development): nobody can log in.
type noAuth struct{}

func newAuthenticator(string) authenticator { return noAuth{} }

func (noAuth) Authenticate(string, string) error { return errors.New("built without PAM") }
