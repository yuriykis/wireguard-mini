package noise

import (
	"encoding/binary"
	"time"
)

const (
	tai64nTimestampSize = 12
	tai64nBase          = uint64(0x400000000000000a)
	tai64nWhitenerMask  = uint32(0x1000000 - 1)
)

type tai64nTimestamp [tai64nTimestampSize]byte

func newTAI64NTimestamp(t time.Time) tai64nTimestamp {
	var timestamp tai64nTimestamp
	seconds := tai64nBase + uint64(t.Unix())
	nanoseconds := uint32(t.Nanosecond()) &^ tai64nWhitenerMask
	binary.BigEndian.PutUint64(timestamp[:8], seconds)
	binary.BigEndian.PutUint32(timestamp[8:], nanoseconds)
	return timestamp
}
