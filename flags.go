package main

import (
	"flag"
	"log"
)

type cmdFlags struct {
	listen     string
	peer       string
	tunAddress string
	config     string
}

func parseFlags() cmdFlags {
	listenFlag := flag.String("listen", "", "local UDP address (for example 192.0.2.1:51820)")
	peerFlag := flag.String("peer", "", "peer UDP endpoint (for example 192.0.2.2:51820)")
	tunAddressFlag := flag.String("tun-address", "", "local TUN IPv4 address (for example 10.0.0.1/24)")
	configFlag := flag.String("config", "", "JSON file with the role and keys (for example left.json)")
	flag.Parse()

	if *listenFlag == "" {
		log.Fatal("-listen is required")
	}
	if *peerFlag == "" {
		log.Fatal("-peer is required")
	}
	if *tunAddressFlag == "" {
		log.Fatal("-tun-address is required")
	}
	if *configFlag == "" {
		log.Fatal("-config is required")
	}

	return cmdFlags{
		listen:     *listenFlag,
		peer:       *peerFlag,
		tunAddress: *tunAddressFlag,
		config:     *configFlag,
	}
}
