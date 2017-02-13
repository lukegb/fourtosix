package tls

import (
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

const (
	maxMessageLength = 65536 // same as maxMessageLength from crypto/tls

	contentTypeAlert     uint8 = 21
	contentTypeHandshake uint8 = 22

	alertLevelFatal uint8 = 2

	handshakeTypeClientHello uint8 = 1

	alertInternalError    uint8 = 80
	alertUnrecognizedName uint8 = 112

	extensionServerName uint16 = 0
)

type Dialer interface {
	Dial(network, address string) (net.Conn, error)
}

type tlsError struct {
	err   error
	alert uint8
}

func (err *tlsError) Error() string {
	return err.err.Error()
}

func tlsErrorf(alert uint8, msgf string, params ...interface{}) *tlsError {
	return &tlsError{
		err:   fmt.Errorf(msgf, params...),
		alert: alert,
	}
}

type ProtocolVersion struct {
	Major, Minor uint8
}

type ClientHello struct {
	ProtocolVersion ProtocolVersion
	ServerName      string
}

type MemorizingReader struct {
	r   io.Reader
	buf []byte
}

func (mr *MemorizingReader) Read(b []byte) (n int, err error) {
	n, err = mr.r.Read(b)
	mr.buf = append(mr.buf, b[:n]...)
	return n, err
}

func readRecord(r io.Reader, contentType uint8) ([]byte, error) {
	head := make([]byte, 5)
	if n, err := r.Read(head); err != nil {
		return nil, err
	} else if n != 5 {
		return nil, fmt.Errorf("read %d bytes, wanted %d", n, 5)
	}

	if head[0] != contentType {
		return nil, fmt.Errorf("unexpected content type %d, wanted %d", head[0], contentType)
	}

	ln := uint16(head[3])<<8 | uint16(head[4])
	fragment := make([]byte, ln)
	if n, err := r.Read(fragment); err != nil {
		return nil, err
	} else if n != int(ln) {
		return nil, fmt.Errorf("read %d bytes of fragment, wanted %d", n, ln)
	}

	return fragment, nil
}

func readClientHello(r io.Reader) (hi *ClientHello, err error) {
	buf, err := readRecord(r, contentTypeHandshake)
	if err != nil {
		return nil, err
	}
	// read message length
	if buf[0] != handshakeTypeClientHello {
		return nil, tlsErrorf(alertInternalError, "expected handshake type ClientHello (%d), got %d", handshakeTypeClientHello, buf[0])
	}
	msgLen := int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
	if msgLen > maxMessageLength {
		return nil, tlsErrorf(alertInternalError, "handshake message of length %d bytes exceeds maximum of %d bytes", msgLen, maxMessageLength)
	}

	for len(buf) < 4+msgLen {
		fmt.Println(len(buf))
		nbuf, err := readRecord(r, contentTypeHandshake)
		if err != nil {
			return nil, err
		}
		buf = append(buf, nbuf...)
	}

	hi = &ClientHello{}
	hi.ProtocolVersion.Major = buf[4]
	hi.ProtocolVersion.Minor = buf[5]
	if hi.ProtocolVersion.Major < 3 || (hi.ProtocolVersion.Major == 3 && hi.ProtocolVersion.Minor < 3) {
		return nil, fmt.Errorf("client offered version %d, %d which is less than our minimum of 3, 3", hi.ProtocolVersion.Major, hi.ProtocolVersion.Minor)
	}

	// skip session ID
	sessionIdLen := int(buf[38])
	if sessionIdLen < 0 || sessionIdLen > 32 || len(buf) < 39+sessionIdLen {
		return nil, fmt.Errorf("sessionIdLen was %d, out of range! min=0, max=32, datamax=%d", sessionIdLen, len(buf)-39)
	}
	buf = buf[39+sessionIdLen:]
	if len(buf) < 2 {
		return nil, fmt.Errorf("insufficient data in buffer after trimming session ID, have %d bytes", len(buf))
	}

	// skip cipher suites
	cipherSuiteLen := int(buf[0])<<16 | int(buf[1])
	if cipherSuiteLen%2 == 1 || len(buf) < 2+cipherSuiteLen {
		return nil, fmt.Errorf("cipherSuiteLen was %d; either not even or buffer too short", cipherSuiteLen)
	}
	buf = buf[2+cipherSuiteLen:]

	// skip compression methods
	compressionMethodsLen := int(buf[0])
	if len(buf) < 1+compressionMethodsLen {
		return nil, fmt.Errorf("compressionMethodsLen was %d; buffer too short", compressionMethodsLen)
	}
	buf = buf[1+compressionMethodsLen:]

	if len(buf) == 0 {
		// no extensions
		return hi, nil
	}
	if len(buf) < 2 {
		return nil, fmt.Errorf("buf too short when parsing extensions")
	}

	extensionsLength := int(buf[0])<<8 | int(buf[1])
	buf = buf[2:]
	if extensionsLength != len(buf) {
		return nil, fmt.Errorf("mismatch in claimed length of extensions (%d) vs. length of buffer (%d)", extensionsLength, len(buf))
	}

	for len(buf) != 0 {
		if len(buf) < 4 {
			return nil, fmt.Errorf("not enough bytes left to parse an extension; len(buf) = %d", len(buf))
		}
		extension := uint16(buf[0])<<8 | uint16(buf[1])
		length := int(buf[2])<<8 | int(buf[3])
		buf = buf[4:]
		if len(buf) < length {
			return nil, fmt.Errorf("claimed length of extension (%d) is larger than remaining buffer (%d)", length, len(buf))
		}

		extbuf := buf[:length]
		buf = buf[length:]
		if extension != extensionServerName {
			// ignore
			continue
		}

		// server name indication!
		serverNameCount := uint16(extbuf[0])<<8 | uint16(extbuf[1])
		extbuf = extbuf[2:]
		if len(extbuf) != int(serverNameCount) {
			return nil, fmt.Errorf("serverNameCount (%d) doesn't match extension length (%d)", serverNameCount, len(extbuf))
		}
		for len(extbuf) > 0 {
			if len(extbuf) < 3 {
				return nil, fmt.Errorf("serverName, not enough bytes to read name")
			}
			nameType := int(extbuf[0])
			if nameType != 0 {
				return nil, tlsErrorf(alertUnrecognizedName, "unsupported name_type %d", nameType)
			}

			nameLen := uint16(extbuf[1])<<8 | uint16(extbuf[2])
			extbuf = extbuf[3:]
			hi.ServerName = string(extbuf[:nameLen])
			if len(extbuf) < int(nameLen) {
				return nil, fmt.Errorf("not enough bytes (buffer has %d) to read server_name of %d bytes", len(extbuf), nameLen)
			}
			extbuf = extbuf[nameLen:]
		}
	}

	return hi, nil
}

func sendTLSAlert(w io.Writer, alert uint8) error {
	abuf := make([]byte, 7)
	abuf[0] = contentTypeAlert

	// set protocolversion
	abuf[1] = 3
	abuf[2] = 1

	// set length of payload
	abuf[3] = 0
	abuf[4] = 2

	abuf[5] = alertLevelFatal
	abuf[6] = alert

	_, err := w.Write(abuf)
	return err
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

type Listener struct {
	RemotePort int

	AllowedHosts    []string
	allowedHostsMap map[string]bool

	HostnameIsAllowed func(string) bool

	MakeDialer func(net.Conn, ClientHello) *net.Dialer

	ForceNetwork string
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

func DialUnderSubnet(subnet string) (func(net.Conn, ClientHello) *net.Dialer, error) {
	localNet, localMask, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, err
	}
	if ones, _ := localMask.Mask.Size(); ones > 96 {
		return nil, fmt.Errorf("subnet mask %s is too small; must be at most 96 bits to fit IPv4 addresses", localMask.String())
	} else if ones == 0 {
		return nil, fmt.Errorf("subnet mask %s is faulty", localMask.String())
	}

	return func(conn net.Conn, hi ClientHello) *net.Dialer {
		localIP := make(net.IP, len(localNet))
		copy(localIP, localNet)
		remoteIP := conn.RemoteAddr()
		copy(localIP[13:], remoteIP.(*net.TCPAddr).IP.To4())
		fmt.Println(localIP)

		return &net.Dialer{
			LocalAddr: &net.TCPAddr{
				IP: localIP,
				Port: 0,
			},
		}
	}, nil
}
