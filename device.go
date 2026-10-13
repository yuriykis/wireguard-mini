package main

import (
	"encoding/base64"
	"io"
	"log"
	"net"
	"os"

	"wireguard-mini/noise"
)

type device struct {
	conn     *net.UDPConn
	tunFile  *os.File
	peerAddr *net.UDPAddr
	config   config
	session  noise.Session

	initiatorEphemeralPrivateKey noise.PrivateKey
	handshakeState               noise.HandshakeState
}

func newDevice(conn *net.UDPConn, tunFile *os.File, peerAddr *net.UDPAddr, config config) *device {
	return &device{
		conn:     conn,
		tunFile:  tunFile,
		peerAddr: peerAddr,
		config:   config,
		session: noise.Session{
			Keys: noise.TransportKeys{
				Send:    [noise.HashSize]byte{1},
				Receive: [noise.HashSize]byte{1},
			},
		},
	}
}

func (d *device) start() {
	if d.config.Initiator {
		d.sendHandshakeInitiation()
	}
	go d.receiveLoop()
	go d.sendLoop()
}

func (d *device) sendHandshakeInitiation() {
	initiation, ephemeralPrivateKey, handshakeState, err := noise.CreateInitiation(d.config.PrivateKey, d.config.PeerPublicKey)
	if err != nil {
		log.Fatalf("could not create handshake initiation: %v", err)
	}
	written, err := d.conn.WriteToUDP(initiation.MarshalBinary(), d.peerAddr)
	if err != nil {
		log.Fatalf("could not send handshake initiation: %v", err)
	}
	log.Printf("handshake initiation sent=%d peer=%s", written, d.peerAddr)
	d.initiatorEphemeralPrivateKey = ephemeralPrivateKey
	d.handshakeState = handshakeState
}

func (d *device) sendLoop() {
	buf := make([]byte, 65535)

	for {
		n, err := d.tunFile.Read(buf)
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

		sealed, err := d.session.Seal(buf[:n])
		if err != nil {
			log.Printf("could not seal packet: %v", err)
			continue
		}

		written, err := d.conn.WriteToUDP(sealed, d.peerAddr)
		if err != nil {
			log.Printf("could not send packet to peer: %v", err)
			continue
		}
		if written != len(sealed) {
			log.Printf("could not send packet to peer: %v", io.ErrShortWrite)
			continue
		}
		log.Printf("sent=%d peer=%s", written, d.peerAddr)
	}
}

func (d *device) receiveLoop() {
	buf := make([]byte, 65535)

	for {
		n, source, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("could not receive packet from UDP: %v", err)
			return
		}

		switch buf[0] {
		case noise.HandshakeInitiationType:
			d.handleInitiation(buf[:n], source)
		case noise.HandshakeResponseType:
			d.handleResponse(buf[:n], source)
		case noise.TransportDataType:
			d.handleTransportData(buf[:n], source)
		}
	}
}

func (d *device) handleInitiation(msg []byte, source *net.UDPAddr) {
	log.Printf("handshake initiation received=%d peer=%s", len(msg), source)
	initiation, initiatorPubKey, timestamp, state, err := noise.ConsumeInitiation(d.config.PrivateKey, msg)
	if err != nil {
		log.Printf("could not consume handshake initiation from UDP peer %s: %v", source, err)
		return
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
		return
	}

	written, err := d.conn.WriteToUDP(response.MarshalBinary(), source)
	if err != nil {
		log.Printf("could not send handshake response to UDP peer %s: %v", source, err)
		return
	}
	log.Printf("handshake response sent=%d peer=%s", written, source)
}

func (d *device) handleResponse(msg []byte, source *net.UDPAddr) {
	log.Printf("handshake response received=%d peer=%s", len(msg), source)
	response, _, err := noise.ConsumeResponse(d.config.PrivateKey, d.initiatorEphemeralPrivateKey, msg, d.handshakeState)
	if err != nil {
		log.Printf("could not consume handshake response: %v", err)
		return
	}
	log.Printf(
		"handshake response consumed responderEphemeralPublicKey.=%s",
		base64.StdEncoding.EncodeToString(response.UnencryptedEphemeral[:]),
	)
}

func (d *device) handleTransportData(msg []byte, source *net.UDPAddr) {
	opened, err := d.session.Open(msg)
	if err != nil {
		log.Printf("could not open packet from UDP peer %s: %v", source, err)
		return
	}

	packet, err := parseIPv4Packet(opened)
	if err != nil {
		log.Printf("invalid packet from UDP peer %s: %v", source, err)
		return
	}

	log.Printf(
		"received=%d peer=%s protocol=%d source=%s destination=%s",
		len(msg),
		source,
		packet.protocol,
		packet.source,
		packet.destination,
	)

	written, err := d.tunFile.Write(opened)
	if err != nil {
		log.Printf("could not write packet to TUN: %v", err)
		return
	}
	if written != len(opened) {
		log.Printf("could not write packet to TUN: %v", io.ErrShortWrite)
		return
	}
	log.Printf("written=%d to=tun0", written)
}
