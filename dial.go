package fourtosix

import (
	"context"
	"fmt"
	"net"
	"time"
)

const (
	subnetMaskFourInSix = 96
	dialTimeout         = 3 * time.Second
)

var (
	DefaultDialer Dialer = &net.Dialer{
		Timeout: dialTimeout,
	}
)

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type Context interface{}

func DialUnderSubnet(subnet string) (func(net.Conn, Context) Dialer, error) {
	localNet, localMask, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, err
	}
	if ones, _ := localMask.Mask.Size(); ones > subnetMaskFourInSix {
		return nil, fmt.Errorf("subnet mask %s is too small; must be at most %d bits to fit IPv4 addresses", localMask.String(), subnetMaskFourInSix)
	} else if ones == 0 {
		return nil, fmt.Errorf("subnet mask %s is faulty", localMask.String())
	}

	return func(conn net.Conn, ctx Context) Dialer {
		localIP := make(net.IP, len(localNet))
		copy(localIP, localNet)
		remoteIP := conn.RemoteAddr()
		copy(localIP[13:], remoteIP.(*net.TCPAddr).IP.To4())

		return &net.Dialer{
			Timeout: dialTimeout,
			LocalAddr: &net.TCPAddr{
				IP:   localIP,
				Port: 0,
			},
		}
	}, nil
}
