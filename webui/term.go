package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/creack/pty"
)

// A root shell in the browser (xterm.js) over a WebSocket at /term.
//
// Opening one needs a login session (no access tokens) and a fresh
// confirmation, like any change. The shell runs as the logged in user
// ("su -l USER"). It closes when the session ends (logout or expiry), after
// termIdle without input, or when the page goes away.
//
// Browser to server: binary messages are keyboard input, text messages are
// JSON {"cols":N,"rows":N} to resize. Server to browser: binary output.

const (
	termIdle     = 15 * time.Minute
	maxTerminals = 4
)

// termCheck is how often an open terminal checks its session
var termCheck = 20 * time.Second

var termCount atomic.Int32

// termCommand starts the shell for user; tests replace it.
var termCommand = func(user string) *exec.Cmd {
	c := exec.Command("/bin/su", "-l", user)
	c.Env = []string{"TERM=xterm-256color", "LANG=C.UTF-8"}
	c.Dir = "/"
	return c
}

// sameOrigin: the WebSocket must come from a page of this UI, because
// browsers send the cookie with cross-site WebSocket requests too.
func sameOrigin(r *http.Request) bool {
	u, err := url.Parse(r.Header.Get("Origin"))
	return err == nil && u.Scheme == "https" && u.Host == r.Host
}

func (s *server) terminal(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		text(w, http.StatusForbidden, "wrong origin\n")
		return
	}
	p := s.identify(r)
	if p == nil || p.viaToken() {
		text(w, http.StatusUnauthorized, "login required\n")
		return
	}
	if !s.st.steppedUp(p.session, s.now()) {
		text(w, http.StatusForbidden, "confirm first\n")
		return
	}
	if termCount.Add(1) > maxTerminals {
		termCount.Add(-1)
		text(w, http.StatusTooManyRequests, "too many terminals open\n")
		return
	}
	defer termCount.Add(-1)

	// the server's read and write timeouts must not end a long session
	rc := http.NewResponseController(w)
	rc.SetReadDeadline(time.Time{})
	rc.SetWriteDeadline(time.Time{})
	conn, err := websocket.Accept(w, r, nil) // checks Origin against Host as well
	if err != nil {
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(64 << 10)

	cmd := termCommand(p.user)
	f, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: 80, Rows: 24})
	if err != nil {
		conn.Close(websocket.StatusInternalError, "could not start a shell")
		return
	}
	s.st.log(s.now(), p.user, "terminal", "opened")
	// Reads and writes get their own contexts: cancelling one would drop the
	// connection before the close message with the reason is sent.
	done := make(chan struct{})
	var once sync.Once
	reason := "closed"
	stop := func(why string) { once.Do(func() { reason = why; close(done) }) }
	var lastInput atomic.Int64
	lastInput.Store(s.now().UnixNano())

	// shell output to the browser
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := f.Read(buf)
			if n > 0 {
				wctx, c := context.WithTimeout(context.Background(), 30*time.Second)
				werr := conn.Write(wctx, websocket.MessageBinary, buf[:n])
				c()
				if werr != nil {
					stop("closed")
					return
				}
			}
			if err != nil {
				stop("shell exited")
				return
			}
		}
	}()
	// browser input to the shell
	go func() {
		for {
			typ, msg, err := conn.Read(context.Background())
			if err != nil {
				stop("closed")
				return
			}
			if typ == websocket.MessageText {
				var sz struct{ Cols, Rows uint16 }
				if json.Unmarshal(msg, &sz) == nil && sz.Cols > 0 && sz.Rows > 0 && sz.Cols <= 1000 && sz.Rows <= 1000 {
					pty.Setsize(f, &pty.Winsize{Cols: sz.Cols, Rows: sz.Rows})
				}
				continue
			}
			lastInput.Store(s.now().UnixNano())
			if _, err := f.Write(msg); err != nil {
				stop("shell exited")
				return
			}
		}
	}()
	// the session must stay valid; typing keeps it alive
	go func() {
		t := time.NewTicker(termCheck)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
			}
			idle := s.now().Sub(time.Unix(0, lastInput.Load()))
			if idle > termIdle {
				stop("idle")
				return
			}
			alive := false
			if idle < 2*termCheck {
				_, alive = s.st.session(p.session, s.now())
			} else {
				alive = s.st.sessionAlive(p.session, s.now())
			}
			if !alive {
				stop("logged out")
				return
			}
		}
	}()

	<-done
	conn.Close(websocket.StatusNormalClosure, reason)
	f.Close()
	if cmd.Process != nil {
		cmd.Process.Signal(os.Kill)
		cmd.Wait()
	}
	s.st.log(s.now(), p.user, "terminal", reason)
}

// sessionAlive reports whether a session is live without refreshing it.
func (s *store) sessionAlive(token string, now time.Time) bool {
	var n int
	s.db.QueryRow(`SELECT count(*) FROM sessions WHERE token_hash = ? AND seen > ? AND created > ?`,
		hashToken(token), now.Add(-idleTimeout).Unix(), now.Add(-maxSessionAge).Unix()).Scan(&n)
	return n == 1
}

// termReady answers the UI's check before it opens the WebSocket, so the
// usual confirmation dialog can run first.
func (s *server) termReady(w http.ResponseWriter, r *http.Request, p *principal) {
	if p.viaToken() {
		text(w, http.StatusForbidden, "not with an access token\n")
		return
	}
	if s.requireStepUp(w, r, p) {
		text(w, http.StatusOK, fmt.Sprintf("ok, closes after %d minutes without input\n", int(termIdle/time.Minute)))
	}
}
