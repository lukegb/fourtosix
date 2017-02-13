package main

import (
	"flag"
	"log"
	"net"

	"github.com/lukegb/fourtosix"
	"github.com/lukegb/fourtosix/tls"
)

var (
	tlsListenPort   = flag.String("tls-listen", ":443", "port to listen on for TLS connection; don't listen if empty")
	tlsPermitSuffix = flag.String("tls-permit-suffix", "", "comma-separated list of suffixes we will permit proxying for")

	fourToSixSubnet = flag.String("v4-subnet", "", "CIDR of subnet to send requests from (e.g. 64:ff96::/96) - this is the IPv6 subnet that will appear in logs for proxied IPs. If left blank, will use default IPv6 address (not recommended!)")
)

func main() {
	flag.Parse()

	var makeDialer func(net.Conn, fourtosix.Context) fourtosix.Dialer
	if *fourToSixSubnet != "" {
		log.Printf("Using subnet %q for outbound IPv6 connections", *fourToSixSubnet)
		var err error
		if makeDialer, err = fourtosix.DialUnderSubnet(*fourToSixSubnet); err != nil {
			log.Fatalf("create dialer factory: %v", err)
		}
	} else {
		log.Println("[WARNING] Using default host IPv6 address for outbound IPv6!")
	}

	if *tlsListenPort != "" {
		l := &tls.Listener{
			MakeDialer: makeDialer,
		}
		log.Printf("[TLS] listening on %q", *tlsListenPort)
		go log.Fatal(l.Listen("tcp", *tlsListenPort))
	}

	var c chan struct{}
	<-c
}
