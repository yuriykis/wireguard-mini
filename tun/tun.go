package tun

import (
	"os"
	"syscall"
	"unsafe"
)

const (
	tunsetiff = 0x400454ca // TUNSETIFF from <linux/if_tun.h>
	iffTun    = 0x0001     // IFF_TUN
	iffNoPI   = 0x1000     // IFF_NO_PI
)

type ifreq struct {
	name  [16]byte
	flags uint16
	_     [22]byte
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
