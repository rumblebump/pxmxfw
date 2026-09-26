package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestTerminal(t *testing.T) {
	e := newEnv(t)
	termCheck = 50 * time.Millisecond
	termCommand = func(user string) *exec.Cmd { return exec.Command("sh", "-c", "echo hello $0; exec cat", user) }
	srv := httptest.NewTLSServer(e.h)
	defer srv.Close()
	c := e.login("root", "pw", "")
	origin := srv.URL
	dial := func(origin string) (*websocket.Conn, *http.Response, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		h := http.Header{}
		h.Set("Origin", origin)
		h.Set("Cookie", cookieName+"="+c)
		return websocket.Dial(ctx, "wss"+strings.TrimPrefix(srv.URL, "https")+"/term", &websocket.DialOptions{HTTPClient: srv.Client(), HTTPHeader: h})
	}
	if _, res, err := dial(origin); err == nil || res == nil || res.StatusCode != 403 {
		t.Fatalf("terminal without confirmation: %v %v", err, res)
	}
	e.expect(e.do(req{method: "POST", query: "action=term", cookie: c}), 403, "term check needs confirmation")
	e.expect(e.do(req{method: "POST", query: "action=stepup", body: `{"password":"pw"}`, cookie: c}), 200, "stepup")
	e.expect(e.do(req{method: "POST", query: "action=term", cookie: c}), 200, "term check")
	if _, res, err := dial("https://evil.example"); err == nil || res == nil || res.StatusCode != 403 {
		t.Fatalf("cross-origin terminal: %v %v", err, res)
	}

	conn, _, err := dial(origin)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var out strings.Builder
	readUntil := func(want string) {
		t.Helper()
		for !strings.Contains(out.String(), want) {
			_, b, err := conn.Read(ctx)
			if err != nil {
				t.Fatalf("waiting for %q, got %q: %v", want, out.String(), err)
			}
			out.Write(b)
		}
	}
	readUntil("hello root")
	conn.Write(ctx, websocket.MessageText, []byte(`{"cols":100,"rows":30}`))
	conn.Write(ctx, websocket.MessageBinary, []byte("abc\n"))
	readUntil("abc")

	// logging out ends the terminal
	e.expect(e.do(req{method: "POST", query: "action=logout", cookie: c}), 200, "logout")
	for {
		if _, _, err := conn.Read(ctx); err != nil {
			if websocket.CloseStatus(err) != websocket.StatusNormalClosure || !strings.Contains(err.Error(), "logged out") {
				t.Fatalf("close after logout: %v", err)
			}
			break
		}
	}
}
