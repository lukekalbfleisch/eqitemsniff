package analyzer

import (
	"encoding/hex"
	"fmt"
)

// Zone represents a zone op entry
type Zone struct {
	Character string
	Shortname string
	Longname  string
}

func (a *Analyzer) zoneScan(packet *EQPacket) error {
	dataSize := len(packet.Data)
	if dataSize < len(a.zonePattern)+50 {
		return nil
	}
	idx := -1
	isFound := false
	for idx = 0; idx < dataSize-len(a.zonePattern); idx++ {
		if hex.EncodeToString(packet.Data[idx:idx+len(a.zonePattern)]) == hex.EncodeToString(a.zonePattern) {
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

	fmt.Println(zone)
	return nil
}
