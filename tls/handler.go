package tls

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/lukegb/fourtosix"
)

type Handler struct {
	RemotePort int

	AllowedHostSuffixes []string

	HostnameIsAllowed func(string) bool

	MakeDialer func(net.Conn, fourtosix.Context) fourtosix.Dialer

	ForceNetwork string
}

func (h *Handler) handle(conn net.Conn) {
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

	rport := h.RemotePort
	if rport == 0 {
		rport = 443
	}

	rnet := h.ForceNetwork
	if rnet == "" {
		rnet = "tcp"
	}

	if h.HostnameIsAllowed != nil && !h.HostnameIsAllowed(hi.ServerName) {
		log.Printf("[%s] connect %s blocked: hostname not allowed", conn.RemoteAddr(), hi.ServerName)
		sendTLSAlert(conn, alertUnrecognizedName)
		return
	}

	var dialer fourtosix.Dialer
	if h.MakeDialer != nil {
		dialer = h.MakeDialer(conn, *hi)
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
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		io.Copy(conn, rconn)
		wg.Done()
	}()
	go func() {
		io.Copy(rconn, conn)
		wg.Done()
	}()

	wg.Wait()
	log.Printf("[%s] closing connection", conn.RemoteAddr())
}

func (h *Handler) checkHostname(hostname string) bool {
	// TODO(lukegb): maybe use a trie of reversed hostname prefixes
	for _, s := range h.AllowedHostSuffixes {
		if strings.HasSuffix(hostname, s) {
			return true
		}
	}
	return false
}

func (h *Handler) Serve(l net.Listener) error {
	if h.HostnameIsAllowed == nil && h.AllowedHostSuffixes != nil {
		h.HostnameIsAllowed = h.checkHostname
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept: %v", err)
		}
		go h.handle(conn)
	}
}
