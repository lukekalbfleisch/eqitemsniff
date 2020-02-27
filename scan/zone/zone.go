package zone

import (
	"encoding/hex"
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/xackery/eqitemsniff/analyzer"
)

var zonePattern []byte

// Zone represents a zone op entry
type Zone struct {
	Character string
	Shortname string
	Longname  string
}

func init() {
	zonePattern, _ = hex.DecodeString("aa4b2c")
}

// Scan returns a zone struct
func Scan(packet *analyzer.EQPacket) *Zone {
	dataSize := len(packet.Data)
	if dataSize < len(zonePattern)+50 {
		return nil
	}
	if dataSize < 300 {
		return nil
	}

	idx := -1
	isFound := false
	for idx = 0; idx < dataSize-len(zonePattern); idx++ {
		if hex.EncodeToString(packet.Data[idx:idx+len(zonePattern)]) == hex.EncodeToString(zonePattern) {
			isFound = true
			break
		}
	}
	if !isFound {
		return nil
	}

	idx += 3
	zone := &Zone{}

	lastIdx := idx
	tData := []byte{}
	for ; packet.Data[idx] != 0x00 && idx < len(packet.Data); idx++ {
		tData = append(tData, packet.Data[idx])
	}
	zone.Character = fmt.Sprintf("%s", tData)
	idx = lastIdx + 64
	lastIdx = idx
	tData = []byte{}
	for ; packet.Data[idx] != 0x00 && idx < len(packet.Data); idx++ {
		tData = append(tData, packet.Data[idx])
	}
	zone.Shortname = fmt.Sprintf("%s", tData)
	idx = lastIdx + 128
	tData = []byte{}
	for ; packet.Data[idx] != 0x00 && idx < len(packet.Data); idx++ {
		tData = append(tData, packet.Data[idx])
	}
	zone.Longname = fmt.Sprintf("%s", tData)

	log.Debug().Interface("zone", zone).Msg("got new zone")
	return zone
}
