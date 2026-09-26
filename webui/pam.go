//go:build cgo && !nopam

package main

/*
#cgo LDFLAGS: -lpam
#include <security/pam_appl.h>
#include <stdlib.h>
#include <string.h>

struct pxm_creds { const char *user; const char *pass; };

static int pxm_conv(int n, const struct pam_message **msg, struct pam_response **resp, void *data) {
	struct pxm_creds *c = data;
	struct pam_response *r;
	int i;

	if (n <= 0)
		return PAM_CONV_ERR;
	r = calloc(n, sizeof *r);
	if (!r)
		return PAM_BUF_ERR;
	for (i = 0; i < n; i++) {
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF: r[i].resp = strdup(c->pass); break;
		case PAM_PROMPT_ECHO_ON:  r[i].resp = strdup(c->user); break;
		case PAM_ERROR_MSG:
		case PAM_TEXT_INFO:       break;
		default:
			while (i-- > 0)
				free(r[i].resp);
			free(r);
			return PAM_CONV_ERR;
		}
	}
	*resp = r;
	return PAM_SUCCESS;
}

static int pxm_auth(const char *service, const char *user, const char *pass) {
	struct pxm_creds c = { user, pass };
	struct pam_conv conv = { pxm_conv, &c };
	pam_handle_t *h = NULL;
	int rc = pam_start(service, user, &conv, &h);

	if (rc != PAM_SUCCESS)
		return rc;
	rc = pam_authenticate(h, PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK);
	if (rc == PAM_SUCCESS)
		rc = pam_acct_mgmt(h, PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK);
	pam_end(h, rc);
	return rc;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// pamAuth checks a user and password against the PAM service (the stack in
// /etc/pam.d/SERVICE), including account checks such as expiry.
type pamAuth struct{ service string }

func newAuthenticator(service string) authenticator { return pamAuth{service} }

func (p pamAuth) Authenticate(user, pass string) error {
	cs, cu := C.CString(p.service), C.CString(user)
	cp := C.CString(pass)
	defer func() {
		C.memset(unsafe.Pointer(cp), 0, C.size_t(len(pass)))
		C.free(unsafe.Pointer(cp))
		C.free(unsafe.Pointer(cu))
		C.free(unsafe.Pointer(cs))
	}()
	if rc := C.pxm_auth(cs, cu, cp); rc != C.PAM_SUCCESS {
		return fmt.Errorf("pam: error %d", int(rc))
	}
	return nil
}
