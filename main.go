package main

import (
	"context"
	"encoding/base64"
	"io"
	"log"
	"net"
	"os"
	"os/signal"

	"wireguard-mini/noise"
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

	var (
		initiatorEphemeralPrivateKey noise.PrivateKey
		handshakeState               noise.HandshakeState
	)
	if config.Initiator {
		initiatorEphemeralPrivateKey, handshakeState = sendHandshakeInitiation(udpConn, peerAddr, config)
	}

	tunFile := setupTUN(flags.tunAddress)
	defer func() {
		if err := tunFile.Close(); err != nil {
			log.Printf("could not close tun0: %v", err)
		}
	}()

	session := noise.Session{
		Keys: noise.TransportKeys{
			Send:    [noise.HashSize]byte{1},
			Receive: [noise.HashSize]byte{1},
		},
	}

	go receivePackets(udpConn, tunFile, &session, config.PrivateKey, initiatorEphemeralPrivateKey, handshakeState)
	go sendPackets(tunFile, udpConn, peerAddr, &session)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	<-ctx.Done()
	log.Print("interrupted, shutting down")
}

func sendPackets(tunFile *os.File, udpConn *net.UDPConn, peerAddr *net.UDPAddr, session *noise.Session) {
	buf := make([]byte, 65535)

	for {
		n, err := tunFile.Read(buf)
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

		sealed, err := session.Seal(buf[:n])
		if err != nil {
			log.Printf("could not seal packet: %v", err)
			continue
		}

		written, err := udpConn.WriteToUDP(sealed, peerAddr)
		if err != nil {
			log.Printf("could not send packet to peer: %v", err)
			continue
		}
		if written != len(sealed) {
			log.Printf("could not send packet to peer: %v", io.ErrShortWrite)
			continue
		}
		log.Printf("sent=%d peer=%s", written, peerAddr)
	}
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

func sendHandshakeInitiation(udpConn *net.UDPConn, peerAddr *net.UDPAddr, config config) (noise.PrivateKey, noise.HandshakeState) {
	initiation, ephemeralPrivateKey, handshakeState, err := noise.CreateInitiation(config.PrivateKey, config.PeerPublicKey)
	if err != nil {
		log.Fatalf("could not create handshake initiation: %v", err)
	}
	written, err := udpConn.WriteToUDP(initiation.MarshalBinary(), peerAddr)
	if err != nil {
		log.Fatalf("could not send handshake initiation: %v", err)
	}
	log.Printf("handshake initiation sent=%d peer=%s", written, peerAddr)
	return ephemeralPrivateKey, handshakeState
}

func receivePackets(conn *net.UDPConn, tunFile *os.File, session *noise.Session, privateKey noise.PrivateKey, initiatorEphemeralPrivateKey noise.PrivateKey, handshakeState noise.HandshakeState) {
	buf := make([]byte, 65535)

	for {
		n, source, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("could not receive packet from UDP: %v", err)
			return
		}

		if buf[0] == noise.HandshakeInitiationType {
			log.Printf("handshake initiation received=%d peer=%s", n, source)
			response := handleHandshakeInitiation(buf[:n], source, privateKey)
			if response == nil {
				continue
			}

			written, err := conn.WriteToUDP(response, source)
			if err != nil {
				log.Printf("could not send handshake response to UDP peer %s: %v", source, err)
				continue
			}
			log.Printf("handshake response sent=%d peer=%s", written, source)
			continue
		}

		if buf[0] == noise.HandshakeResponseType {
			log.Printf("handshake response received=%d peer=%s", n, source)
			handleHandshakeResponse(buf[:n], privateKey, initiatorEphemeralPrivateKey, handshakeState)
			continue
		}

		opened, err := session.Open(buf[:n])
		if err != nil {
			log.Printf("could not open packet from UDP peer %s: %v", source, err)
			continue
		}

		packet, err := parseIPv4Packet(opened)
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

		written, err := tunFile.Write(opened)
		if err != nil {
			log.Printf("could not write packet to TUN: %v", err)
			continue
		}
		if written != len(opened) {
			log.Printf("could not write packet to TUN: %v", io.ErrShortWrite)
			continue
		}
		log.Printf("written=%d to=tun0", written)
	}
}

func handleHandshakeInitiation(buf []byte, source *net.UDPAddr, privateKey noise.PrivateKey) []byte {
	initiation, initiatorPubKey, timestamp, state, err := noise.ConsumeInitiation(privateKey, buf)
	if err != nil {
		log.Printf("could not consume handshake initiation from UDP peer %s: %v", source, err)
		return nil
	}
	log.Printf(
		"handshake initiation consumed peer=%s initiatorPubKey=%s timestamp=%x",
		source,
		base64.StdEncoding.EncodeToString(initiatorPubKey[:]),
		timestamp,
	)

	response, _, err := noise.CreateResponse(initiatorPubKey, initiation, state)
	if err != nil {
		log.Printf("could not create handshake response for UDP peer %s: %v", source, err)
		return nil
	}
	return response.MarshalBinary()
}

func handleHandshakeResponse(buf []byte, privateKey noise.PrivateKey, initiatorEphemeralPrivateKey noise.PrivateKey, handshakeState noise.HandshakeState) {
	response, _, err := noise.ConsumeResponse(privateKey, initiatorEphemeralPrivateKey, buf, handshakeState)
	if err != nil {
		log.Printf("could not consume handshake response: %v", err)
		return
	}
	log.Printf(
		"handshake response consumed responderEphemeralPublicKey.=%s",
		base64.StdEncoding.EncodeToString(response.UnencryptedEphemeral[:]),
	)
}
