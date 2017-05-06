package http

import (
	"bufio"
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

const (
	bufferBytes                = 1024
	hostHeaderPrefix           = "Host: "
	badRequestResponse         = "HTTP/1.0 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nBad Request\r\n"
	serviceUnavailableResponse = "HTTP/1.0 503 Service Unavailable\r\nContent-Type: text/plain\r\n\r\nService Unavailable\r\n"
)

// Handler handles incoming HTTP requests and routes them to a backend based on their HTTP Host header.
type Handler struct {
	MakeDialer          func(net.Conn, fourtosix.Context) fourtosix.Dialer
	HostnameIsAllowed   func(hostname string) bool
	AllowedHostSuffixes []string
}

func hostHeader(r io.Reader) (host string, sawAllHeaders bool, err error) {
	bs := bufio.NewScanner(r)

	// Cap scanner buffer to 1024 bytes, which should be enough for anyone(?)
	bs.Buffer(nil, bufferBytes)

	if !bs.Scan() {
		return "", false, fmt.Errorf("failed to read initial line: %v", bs.Err())
	}

	// Read headers.
	for bs.Scan() {
		ln := bs.Text()
		if ln == "" {
			// Marker for end of headers.
			sawAllHeaders = true
			break
		}

		if !strings.HasPrefix(ln, hostHeaderPrefix) {
			// Not interested in non-Host headers.
			continue
		}

		if host != "" {
			// Multiple Host headers?!?
			return "", false, fmt.Errorf("saw multiple Host headers")
		}

		host = strings.TrimPrefix(ln, hostHeaderPrefix)
	}

	return host, sawAllHeaders, bs.Err()
}

func (h *Handler) handle(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	log.Printf("[%s] got connection", conn.RemoteAddr())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mr := &fourtosix.MemorizingReader{Reader: conn}

	host, sawAllHeaders, err := hostHeader(mr)
	if err != nil {
		log.Printf("[%s] error reading headers: %v", conn.RemoteAddr(), err)
		fmt.Fprintf(conn, badRequestResponse)
		return
	}

	if !sawAllHeaders {
		log.Printf("[%s] failed to read all headers", conn.RemoteAddr())
		fmt.Fprintf(conn, badRequestResponse)
		return
	}
	if host == "" {
		log.Printf("[%s] never saw a Host header", conn.RemoteAddr())
		fmt.Fprintf(conn, badRequestResponse)
		return
	}

	if h.HostnameIsAllowed != nil && !h.HostnameIsAllowed(host) {
		log.Printf("[%s] connect %s blocked: hostname not allowed", conn.RemoteAddr(), hostHeader)
		fmt.Fprintf(conn, badRequestResponse)
		return
	}

	var dialer fourtosix.Dialer
	if h.MakeDialer != nil {
		dialer = h.MakeDialer(conn, hostHeader)
	} else {
		dialer = fourtosix.DefaultDialer
	}

	rconn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, "80"))
	if err != nil {
		log.Printf("[%s] connect %s: %v", conn.RemoteAddr(), host, err)
		fmt.Fprintf(conn, serviceUnavailableResponse)
		return
	}
	defer rconn.Close()
	log.Printf("[%s] connected to %s", conn.RemoteAddr(), host)
	if _, err := rconn.Write(mr.Buffer()); err != nil {
		log.Printf("[%s] send catchup to rconn %s: %v", conn.RemoteAddr(), host, err)
		fmt.Fprintf(conn, serviceUnavailableResponse)
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
	for _, s := range h.AllowedHostSuffixes {
		if strings.HasSuffix(hostname, s) {
			return true
		}
	}
	return false
}

func (h *Handler) Serve(c net.Listener) error {
	if h.HostnameIsAllowed == nil && h.AllowedHostSuffixes != nil {
		h.HostnameIsAllowed = h.checkHostname
	}

	for {
		conn, err := c.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept: %v", err)
		}
		go h.handle(conn)
	}
}
