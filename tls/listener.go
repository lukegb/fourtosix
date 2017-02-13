package tls

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/lukegb/fourtosix"
)

type Listener struct {
	RemotePort int

	AllowedHostSuffixes []string

	HostnameIsAllowed func(string) bool

	MakeDialer func(net.Conn, fourtosix.Context) fourtosix.Dialer

	ForceNetwork string
}

func (l *Listener) handleTLS(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	log.Printf("[%s] got connection", conn.RemoteAddr())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mr := &memorizingReader{r: conn}
	hi, err := readClientHello(mr)
	if err != nil {
		log.Printf("[%s] readClientHello: %v", conn.RemoteAddr(), err)
		alert := alertInternalError
		if tlsErr, ok := err.(*tlsError); ok {
			alert = tlsErr.alert
		}
		sendTLSAlert(conn, alert)
		return
	}
	if hi.ServerName == "" {
		log.Printf("[%s] no server_name", conn.RemoteAddr())
		sendTLSAlert(conn, alertUnrecognizedName)
		return
	}

	rport := l.RemotePort
	if rport == 0 {
		rport = 443
	}

	rnet := l.ForceNetwork
	if rnet == "" {
		rnet = "tcp"
	}

	if l.HostnameIsAllowed != nil && !l.HostnameIsAllowed(hi.ServerName) {
		log.Printf("[%s] connect %s blocked: hostname not allowed", conn.RemoteAddr(), hi.ServerName)
		sendTLSAlert(conn, alertUnrecognizedName)
		return
	}

	var dialer fourtosix.Dialer
	if l.MakeDialer != nil {
		dialer = l.MakeDialer(conn, *hi)
	} else {
		dialer = fourtosix.DefaultDialer
	}

	rconn, err := dialer.DialContext(ctx, rnet, net.JoinHostPort(hi.ServerName, fmt.Sprintf("%d", rport)))
	if err != nil {
		log.Printf("[%s] connect %s: %v", conn.RemoteAddr(), hi.ServerName, err)
		sendTLSAlert(conn, alertUnrecognizedName)
		return
	}
	defer rconn.Close()
	log.Printf("[%s] connected to %s", conn.RemoteAddr(), hi.ServerName)
	if _, err := rconn.Write(mr.buf); err != nil {
		log.Printf("[%s] write ClientHello to rconn %s: %v", conn.RemoteAddr(), hi.ServerName, err)
		sendTLSAlert(conn, alertInternalError)
		return
	}

	// unset deadline
	var zero time.Time
	conn.SetDeadline(zero)

	log.Printf("[%s] gluing connections together", conn.RemoteAddr())
	var done chan struct{}
	go func() {
		io.Copy(conn, rconn)
		close(done)
	}()
	go func() {
		io.Copy(rconn, conn)
		close(done)
	}()

	<-done
	log.Printf("[%s] closing connection", conn.RemoteAddr())
}

func (l *Listener) checkHostname(hostname string) bool {
	// TODO(lukegb): maybe use a trie of reversed hostname prefixes
	for _, s := range l.AllowedHostSuffixes {
		if strings.HasSuffix(hostname, s) {
			return true
		}
	}
	return false
}

func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func (l *Listener) Listen(network, addr string) error {
	ln, err := net.Listen(network, addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}

	if l.HostnameIsAllowed == nil && l.AllowedHostSuffixes != nil {
		l.HostnameIsAllowed = l.checkHostname
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept: %v", err)
		}
		go l.handleTLS(conn)
	}
}
