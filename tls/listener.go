package tls

import (
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

type Listener struct {
	RemotePort int

	AllowedHosts    []string
	allowedHostsMap map[string]bool

	HostnameIsAllowed func(string) bool

	MakeDialer func(net.Conn, ClientHello) Dialer

	ForceNetwork string
}

func (l *Listener) handleTLS(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	log.Printf("[%s] got connection", conn.RemoteAddr())
	mr := &MemorizingReader{r: conn}
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

	var dialer Dialer
	if l.MakeDialer != nil {
		dialer = l.MakeDialer(conn, *hi)
	} else {
		dialer = new(net.Dialer)
	}

	rconn, err := dialer.Dial(rnet, net.JoinHostPort(hi.ServerName, fmt.Sprintf("%d", rport)))
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
	go func() {
		io.Copy(conn, rconn)
		conn.Close()
		rconn.Close()
	}()
	io.Copy(rconn, conn)

	log.Printf("[%s] closing connection", conn.RemoteAddr())
}

func (l *Listener) checkHostname(hostname string) bool {
	return !l.allowedHostsMap[hostname]
}

func (l *Listener) Listen(network, addr string) error {
	ln, err := net.Listen(network, addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}

	if l.HostnameIsAllowed == nil && l.AllowedHosts != nil {
		l.HostnameIsAllowed = l.checkHostname
	}
	if l.AllowedHosts != nil {
		allowedHostsMap := make(map[string]bool)
		for _, h := range l.AllowedHosts {
			allowedHostsMap[h] = true
		}
		l.allowedHostsMap = allowedHostsMap
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept: %v", err)
		}
		go l.handleTLS(conn)
	}
}
