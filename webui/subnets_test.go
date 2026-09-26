package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProposeSubnet(t *testing.T) {
	e := newEnv(t)
	os.WriteFile(filepath.Join(e.etc, "interfaces"), []byte("eth0 role=wan\neth1 role=lan addr=10.20.1.1/24\n"), 0o644)
	os.WriteFile(filepath.Join(e.etc, "wireguard"), []byte("tunnel wg0 port=51820\npeer wg0 key=K allowed=10.20.3.0/25\n"), 0o644)
	c := e.login("root", "pw", "")
	propose := func(want string) {
		t.Helper()
		w := e.do(req{method: "GET", query: "action=propose-subnet&name=vl10", cookie: c})
		if want == "" {
			e.expect(w, 409, "pool full")
			return
		}
		e.expect(w, 200, "propose")
		if got := strings.TrimSpace(w.Body.String()); got != want {
			t.Fatalf("proposed %s, want %s", got, want)
		}
	}
	// .0 is on eth0 (live), .1 in interfaces, .3 overlaps a peer's allowed IPs
	propose("10.20.2.1/24")
	propose("10.20.4.1/24") // .2 was just proposed
	e.now = e.now.Add(25 * time.Hour)
	c = e.login("root", "pw", "")
	propose("10.20.2.1/24") // old proposals expire

	e.expect(e.do(req{method: "POST", query: "action=pref&name=subnet_pool", body: "192.168.100.0/24", cookie: c}), 200, "set pool")
	propose("192.168.100.1/24")
	propose("")
	e.expect(e.do(req{method: "POST", query: "action=pref&name=subnet_pool", body: "10.0.0.0/25", cookie: c}), 200, "set pool")
	e.expect(e.do(req{method: "GET", query: "action=propose-subnet&name=vl10", cookie: c}), 400, "pool smaller than /24")
	e.expect(e.do(req{method: "GET", query: "action=propose-subnet&name=a%20b", cookie: c}), 400, "bad name")
	e.expect(e.do(req{method: "GET", query: "action=propose-subnet&name=vl10"}), 401, "needs login")
}
