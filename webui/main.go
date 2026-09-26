// pxmxfw-webui serves the pxmxfw web UI and its API over HTTPS.
//
// Logins go through PAM (/etc/pam.d/pxmxfw), for root and members of the
// pxmxfw group. Its own state (sessions, TOTP secrets, access tokens,
// preferences, change log) lives in SQLite; the firewall configuration stays
// in /etc/pxmxfw and is changed through the pxmxfw command.
package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

func main() {
	listen := flag.String("listen", ":8443", "address to listen on, ADDR:PORT or PORT")
	www := flag.String("www", "/usr/share/pxmxfw/www", "static files")
	dbPath := flag.String("db", "/var/lib/pxmxfw/webui.db", "SQLite database")
	certFile := flag.String("cert", "/etc/pxmxfw/tls/webui.crt", "TLS certificate (created self-signed if missing)")
	keyFile := flag.String("key", "/etc/pxmxfw/tls/webui.key", "TLS key")
	pamService := flag.String("pam-service", "pxmxfw", "PAM service name")
	group := flag.String("group", "pxmxfw", "besides root, members of this group may log in")
	pxmxfw := flag.String("pxmxfw", "/usr/sbin/pxmxfw", "pxmxfw command")
	etc := flag.String("etc", "/etc/pxmxfw", "pxmxfw configuration directory")
	leases := flag.String("leases", "/var/lib/misc/dnsmasq.leases", "dnsmasq leases file")
	flag.Parse()

	addr := *listen
	if !strings.Contains(addr, ":") {
		addr = ":" + addr
	}
	if err := os.MkdirAll(filepath.Dir(*dbPath), 0o700); err != nil {
		log.Fatal(err)
	}
	st, err := openStore(*dbPath)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	os.Chmod(*dbPath, 0o600)
	if err := ensureCert(*certFile, *keyFile); err != nil {
		log.Fatalf("certificate: %v", err)
	}
	host, _ := os.Hostname()

	s := &server{
		st:      st,
		auth:    newAuthenticator(*pamService),
		allowed: groupMember(*group),
		pxmxfw:  *pxmxfw,
		etc:     *etc,
		leases:  *leases,
		www:     *www,
		host:    host,
		now:     time.Now,
		limit:   newLimiter(time.Now),
	}
	go func() {
		for {
			st.prune(time.Now())
			time.Sleep(10 * time.Minute)
		}
	}()

	srv := &http.Server{
		Addr:              addr,
		Handler:           s.routes(),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      cmdTimeout + 30*time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	log.Printf("pxmxfw web UI on https://%s", addr)
	log.Fatal(srv.ListenAndServeTLS(*certFile, *keyFile))
}

// groupMember allows root and members of group.
func groupMember(group string) func(string) bool {
	return func(name string) bool {
		if name == "root" {
			return true
		}
		g, err := user.LookupGroup(group)
		if err != nil {
			return false
		}
		u, err := user.Lookup(name)
		if err != nil {
			return false
		}
		ids, err := u.GroupIds()
		return err == nil && slices.Contains(ids, g.Gid)
	}
}
