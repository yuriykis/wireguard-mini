package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"wireguard-mini/tun"
)

func main() {
	flags := parseFlags()

	config, err := loadConfig(flags.config)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("config loaded from %s, initiator=%t", flags.config, config.Initiator)

	peerAddr, err := net.ResolveUDPAddr("udp4", flags.peer)
	if err != nil {
		log.Fatalf("invalid -peer address: %v", err)
	}

	udpConn := listenUDP(flags.listen)
	defer func() {
		if err := udpConn.Close(); err != nil {
			log.Printf("could not close UDP socket: %v", err)
		}
	}()
	log.Printf("UDP listening on %s, peer %s", udpConn.LocalAddr(), peerAddr)

	tunFile := setupTUN(flags.tunAddress)
	defer func() {
		if err := tunFile.Close(); err != nil {
			log.Printf("could not close tun0: %v", err)
		}
	}()

	d := newDevice(udpConn, tunFile, peerAddr, config)
	d.start()

	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, syscall.SIGINT, syscall.SIGTERM)
	<-sigch
	log.Print("interrupted, shutting down")
}

func listenUDP(listen string) *net.UDPConn {
	listenAddr, err := net.ResolveUDPAddr("udp4", listen)
	if err != nil {
		log.Fatalf("invalid -listen address: %v", err)
	}
	udpConn, err := net.ListenUDP("udp4", listenAddr)
	if err != nil {
		log.Fatalf("could not listen on UDP %s: %v", listenAddr, err)
	}
	return udpConn
}

func setupTUN(tunAddress string) *os.File {
	tunIP, tunNetwork, err := net.ParseCIDR(tunAddress)
	if err != nil {
		log.Fatalf("invalid -tun-address: %v", err)
	}
	_, addressBits := tunNetwork.Mask.Size()
	if tunIP.To4() == nil || addressBits != 32 {
		log.Fatal("-tun-address must be an IPv4 CIDR")
	}

	tunFile, err := tun.Open("tun0")
	if err != nil {
		log.Fatal(err)
	}
	log.Print("tun0 created, Ctrl-C to remove it")
	if err := tun.SetMTU("tun0", 1420); err != nil {
		log.Fatal(err)
	}
	log.Print("tun0 MTU set to 1420")
	if err := tun.SetIPv4Address("tun0", tunIP, tunNetwork.Mask); err != nil {
		log.Fatal(err)
	}
	log.Printf("tun0 address set to %s", tunAddress)
	if err := tun.SetUp("tun0"); err != nil {
		log.Fatal(err)
	}
	log.Print("tun0 is up")
	return tunFile
}
