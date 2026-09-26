package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Proposed subnets for new interfaces. The UI asks for one when an
// interface is added and gets the first free /24 of a pool (the
// subnet_pool preference, 10.20.0.0/16 by default). A /24 is free when no
// address in the config or in the container is in it, and it was not
// proposed in the last day, so two open browser tabs don't get the same one.
// The config files stay the source of truth; this only remembers proposals.

const (
	defaultPool     = "10.20.0.0/16"
	proposalTimeout = 24 * time.Hour
)

var subnetMu sync.Mutex

const schemaSubnets = `
CREATE TABLE IF NOT EXISTS subnets (
	cidr    TEXT PRIMARY KEY,
	iface   TEXT NOT NULL,
	user    TEXT NOT NULL,
	created INTEGER NOT NULL
);
`

func (s *store) proposed(since time.Time) (map[netip.Prefix]bool, error) {
	rows, err := s.db.Query(`SELECT cidr FROM subnets WHERE created >= ?`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[netip.Prefix]bool{}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		if p, err := netip.ParsePrefix(c); err == nil {
			out[p] = true
		}
	}
	return out, rows.Err()
}

func (s *store) propose(p netip.Prefix, iface, user string, now time.Time) error {
	_, err := s.db.Exec(`INSERT INTO subnets (cidr, iface, user, created) VALUES (?, ?, ?, ?)
		ON CONFLICT(cidr) DO UPDATE SET iface = excluded.iface, user = excluded.user, created = excluded.created`,
		p.String(), iface, user, now.Unix())
	return err
}

// usedPrefixes lists the IPv4 networks in use: addresses and allowed IPs in
// the config files, and every address the container has now.
func (s *server) usedPrefixes() []netip.Prefix {
	var used []netip.Prefix
	add := func(v string) {
		if p, err := netip.ParsePrefix(v); err == nil && p.Addr().Is4() {
			used = append(used, p.Masked())
		}
	}
	for _, f := range []string{"interfaces", "wireguard"} {
		b, _ := os.ReadFile(filepath.Join(s.etc, f))
		for _, field := range strings.Fields(string(b)) {
			k, v, _ := strings.Cut(field, "=")
			switch k {
			case "addr":
				add(v)
			case "allowed":
				for _, a := range strings.Split(v, ",") {
					add(a)
				}
			}
		}
	}
	out, _ := s.command("status")
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		// addr=IFACE ADDRESS/PREFIX
		if rest, ok := strings.CutPrefix(sc.Text(), "addr="); ok {
			if f := strings.Fields(rest); len(f) == 2 {
				add(f[1])
			}
		}
	}
	return used
}

// nextSubnet returns the first /24 in pool that overlaps nothing in used
// and was not proposed recently.
func nextSubnet(pool netip.Prefix, used []netip.Prefix, taken map[netip.Prefix]bool) (netip.Prefix, bool) {
	if !pool.Addr().Is4() || pool.Bits() > 24 {
		return netip.Prefix{}, false
	}
	pool = pool.Masked()
	a := pool.Addr().As4()
	n := 1 << (24 - pool.Bits())
	for i := 0; i < n; i++ {
		base := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 + uint32(i)<<8
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(base >> 24), byte(base >> 16), byte(base >> 8), 0}), 24)
		if taken[p] {
			continue
		}
		free := true
		for _, u := range used {
			if u.Overlaps(p) {
				free = false
				break
			}
		}
		if free {
			return p, true
		}
	}
	return netip.Prefix{}, false
}

// proposeSubnet answers with ADDRESS/24 (the .1 of a free /24) for iface.
func (s *server) proposeSubnet(w http.ResponseWriter, p *principal, iface string) {
	if iface == "" || len(iface) > 15 || strings.ContainsAny(iface, " \t\r\n=/#") {
		text(w, http.StatusBadRequest, "name the interface\n")
		return
	}
	poolText := defaultPool
	if m, err := s.st.prefs(); err == nil && m["subnet_pool"] != "" {
		poolText = m["subnet_pool"]
	}
	pool, err := netip.ParsePrefix(poolText)
	if err != nil || !pool.Addr().Is4() || pool.Bits() > 24 {
		text(w, http.StatusBadRequest, fmt.Sprintf("the subnet pool %q is not an IPv4 network of /24 or larger\n", poolText))
		return
	}
	subnetMu.Lock()
	defer subnetMu.Unlock()
	taken, err := s.st.proposed(s.now().Add(-proposalTimeout))
	if err != nil {
		text(w, http.StatusInternalServerError, "could not read proposals\n")
		return
	}
	next, ok := nextSubnet(pool, s.usedPrefixes(), taken)
	if !ok {
		text(w, http.StatusConflict, fmt.Sprintf("no free /24 left in %s, choose another pool\n", pool))
		return
	}
	if err := s.st.propose(next, iface, p.user, s.now()); err != nil {
		text(w, http.StatusInternalServerError, "could not save the proposal\n")
		return
	}
	gw := next.Addr().Next()
	text(w, http.StatusOK, netip.PrefixFrom(gw, 24).String()+"\n")
}
