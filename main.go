package main

import (
	"flag"
	"io"
	"log"
	"net"
	"os"

	"wireguard-mini/tun"
)

func main() {
	listenFlag := flag.String("listen", "", "local UDP address (for example 192.0.2.1:51820)")
	peerFlag := flag.String("peer", "", "peer UDP endpoint (for example 192.0.2.2:51820)")
	tunAddressFlag := flag.String("tun-address", "", "local TUN IPv4 address (for example 10.0.0.1/24)")
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

	tunIP, tunNetwork, err := net.ParseCIDR(*tunAddressFlag)
	if err != nil {
		log.Fatalf("invalid -tun-address: %v", err)
	}
	_, addressBits := tunNetwork.Mask.Size()
	if tunIP.To4() == nil || addressBits != 32 {
		log.Fatal("-tun-address must be an IPv4 CIDR")
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
	defer func() {
		if err := udpConn.Close(); err != nil {
			log.Printf("could not close UDP socket: %v", err)
		}
	}()
	log.Printf("UDP listening on %s, peer %s", udpConn.LocalAddr(), peerAddr)

	file, err := tun.Open("tun0")
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Printf("could not close tun0: %v", err)
		}
	}()
	log.Print("tun0 created, Ctrl-C to remove it")
	if err := tun.SetMTU("tun0", 1420); err != nil {
		log.Fatal(err)
	}
	log.Print("tun0 MTU set to 1420")
	if err := tun.SetIPv4Address("tun0", tunIP, tunNetwork.Mask); err != nil {
		log.Fatal(err)
	}
	log.Printf("tun0 address set to %s", *tunAddressFlag)
	if err := tun.SetUp("tun0"); err != nil {
		log.Fatal(err)
	}
	log.Print("tun0 is up")
	go receiveUDPPackets(udpConn, file)

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

func receiveUDPPackets(conn *net.UDPConn, tunFile *os.File) {
	buf := make([]byte, 65535)

	for {
		n, source, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("could not receive packet from UDP: %v", err)
			return
		}

		packet, err := parseIPv4Packet(buf[:n])
		if err != nil {
			log.Printf("invalid packet from UDP peer %s: %v", source, err)
			continue
		}

		log.Printf(
			"received=%d peer=%s protocol=%d source=%s destination=%s",
			n,
			source,
			packet.protocol,
			packet.source,
			packet.destination,
		)

		written, err := tunFile.Write(buf[:n])
		if err != nil {
			log.Printf("could not write packet to TUN: %v", err)
			continue
		}
		if written != n {
			log.Printf("could not write packet to TUN: %v", io.ErrShortWrite)
			continue
		}
		log.Printf("written=%d to=tun0", written)
	}
}
