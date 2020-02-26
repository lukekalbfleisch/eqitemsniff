package analyzer

import (
	"fmt"
)

// Item represents an item
type Item struct {
}

func (a *Analyzer) itemScan(packet *EQPacket) error {
	dataSize := len(packet.Data)
	itOffset := -1
	for i, d := range packet.Data {
		if i >= dataSize-1 {
			return nil
		}
		if d == 0x49 && packet.Data[i+1] == 0x54 {
			itOffset = i
			break
		}
	}
	if itOffset == -1 {
		return nil
	}

	return fmt.Errorf("offset at %d", itOffset)
}
