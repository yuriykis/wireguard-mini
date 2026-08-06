package tun

import (
	"os"
	"syscall"
	"unsafe"
)

const (
	tunsetiff  = 0x400454ca // TUNSETIFF from <linux/if_tun.h>
	iffTun     = 0x0001     // IFF_TUN
	iffNoPI    = 0x1000     // IFF_NO_PI
	siocsifmtu = 0x8922     // SIOCSIFMTU from <linux/sockios.h>
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
		file.Close()
		return nil, errno
	}

	return file, nil
}

func SetMTU(name string, mtu int) error {
	socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(socket)

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
