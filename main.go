package main

import (
	"flag"
	"io"
	"log"
	"net"

	"wireguard-mini/tun"
)

func main() {
	listenFlag := flag.String("listen", "", "local UDP address (for example 192.0.2.1:51820)")
	peerFlag := flag.String("peer", "", "peer UDP endpoint (for example 192.0.2.2:51820)")
	flag.Parse()

	if *listenFlag == "" {
		log.Fatal("-listen is required")
	}
	if *peerFlag == "" {
		log.Fatal("-peer is required")
	}

	listenAddr, err := net.ResolveUDPAddr("udp4", *listenFlag)
	if err != nil {
		log.Fatalf("invalid -listen address: %v", err)
	}
	peerAddr, err := net.ResolveUDPAddr("udp4", *peerFlag)
	if err != nil {
		log.Fatalf("invalid -peer address: %v", err)
	}

	udpConn, err := net.ListenUDP("udp4", listenAddr)
	if err != nil {
		log.Fatalf("could not listen on UDP %s: %v", listenAddr, err)
	}
	defer udpConn.Close()
	log.Printf("UDP listening on %s, peer %s", udpConn.LocalAddr(), peerAddr)

	file, err := tun.Open("tun0")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	log.Print("tun0 created, Ctrl-C to remove it")
	if err := tun.SetMTU("tun0", 1420); err != nil {
		log.Fatal(err)
	}
	log.Print("tun0 MTU set to 1420")

	buf := make([]byte, 65535)

	for {
		n, err := file.Read(buf)
		if err != nil {
			log.Fatal(err)
		}

		packet, err := parseIPv4Packet(buf[:n])
		if err != nil {
			log.Printf("invalid packet: %v", err)
			continue
		}

		log.Printf(
			"read=%d totalLength=%d version=%d headerLength=%d protocol=%d source=%s destination=%s",
			n,
			packet.totalLength,
			ipv4Version,
			packet.headerLength,
			packet.protocol,
			packet.source,
			packet.destination,
		)

		written, err := udpConn.WriteToUDP(buf[:n], peerAddr)
		if err != nil {
			log.Printf("could not send packet to peer: %v", err)
			continue
		}
		if written != n {
			log.Printf("could not send packet to peer: %v", io.ErrShortWrite)
			continue
		}
		log.Printf("sent=%d peer=%s", written, peerAddr)
	}
}
