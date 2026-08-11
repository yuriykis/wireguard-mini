package tun

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"
)

const (
	tunsetiff      = 0x400454ca // TUNSETIFF from <linux/if_tun.h>
	iffUp          = 0x0001     // IFF_UP
	iffTun         = 0x0001     // IFF_TUN
	iffNoPI        = 0x1000     // IFF_NO_PI
	siocgifflags   = 0x8913     // SIOCGIFFLAGS from <linux/sockios.h>
	siocsifflags   = 0x8914     // SIOCSIFFLAGS from <linux/sockios.h>
	siocsifaddr    = 0x8916     // SIOCSIFADDR from <linux/sockios.h>
	siocsifmtu     = 0x8922     // SIOCSIFMTU from <linux/sockios.h>
	siocsifnetmask = 0x891c     // SIOCSIFNETMASK from <linux/sockios.h>
)

type ifreq struct {
	name  [16]byte
	flags uint16
	_     [22]byte
}

type ifreqMTU struct {
	name [16]byte
	mtu  int32
	_    [20]byte
}

type ifreqIPv4 struct {
	name    [16]byte
	address syscall.RawSockaddrInet4
	_       [8]byte
}

func Open(name string) (*os.File, error) {
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	var req ifreq
	copy(req.name[:], name)
	req.flags = iffTun | iffNoPI

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		file.Fd(),
		tunsetiff,
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		return nil, errors.Join(errno, file.Close())
	}

	return file, nil
}

func SetMTU(name string, mtu int) error {
	socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer func() {
		_ = syscall.Close(socket)
	}()

	var req ifreqMTU
	copy(req.name[:], name)
	req.mtu = int32(mtu)

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(socket),
		siocsifmtu, // means "set MTU"
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		return errno
	}

	return nil
}

func SetIPv4Address(name string, ip net.IP, mask net.IPMask) error {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return fmt.Errorf("address must be IPv4")
	}
	_, bits := mask.Size()
	if bits != 32 {
		return fmt.Errorf("mask must be IPv4")
	}

	socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer func() {
		_ = syscall.Close(socket)
	}()

	if err := setIPv4(socket, siocsifaddr, name, ipv4); err != nil {
		return err
	}
	if err := setIPv4(socket, siocsifnetmask, name, mask); err != nil {
		return err
	}

	return nil
}

func SetUp(name string) error {
	socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer func() {
		_ = syscall.Close(socket)
	}()

	var req ifreq
	copy(req.name[:], name)

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(socket),
		siocgifflags, // means "get flags" and store them in req.flags
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		return errno
	}

	req.flags |= iffUp
	_, _, errno = syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(socket),
		siocsifflags, // means "set flags" and use req.flags
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		return errno
	}

	return nil
}

func setIPv4(socket int, request uintptr, name string, address []byte) error {
	var req ifreqIPv4
	copy(req.name[:], name)
	req.address.Family = syscall.AF_INET
	copy(req.address.Addr[:], address)

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(socket),
		request,
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		return errno
	}

	return nil
}
