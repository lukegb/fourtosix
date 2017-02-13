package tls

import (
	"fmt"
	"net"
)

type Dialer interface {
	Dial(network, address string) (net.Conn, error)
}

func DialUnderSubnet(subnet string) (func(net.Conn, ClientHello) Dialer, error) {
	localNet, localMask, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, err
	}
	if ones, _ := localMask.Mask.Size(); ones > 96 {
		return nil, fmt.Errorf("subnet mask %s is too small; must be at most 96 bits to fit IPv4 addresses", localMask.String())
	} else if ones == 0 {
		return nil, fmt.Errorf("subnet mask %s is faulty", localMask.String())
	}

	return func(conn net.Conn, hi ClientHello) Dialer {
		localIP := make(net.IP, len(localNet))
		copy(localIP, localNet)
		remoteIP := conn.RemoteAddr()
		copy(localIP[13:], remoteIP.(*net.TCPAddr).IP.To4())

		return &net.Dialer{
			LocalAddr: &net.TCPAddr{
				IP:   localIP,
				Port: 0,
			},
		}
	}, nil
}
