package analyzer

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"
)

// AdvLoot struct
type AdvLoot struct {
	ID        uint16
	Name      string
	Count     uint16
	Timestamp time.Time
	Items     []AdvLootItem
}

// AdvLootItem struct
type AdvLootItem struct {
	ID    uint16
	Name  string
	Count uint16
}

func (a *Analyzer) advlootScan(packet *EQPacket) *AdvLoot {

	maxOffset := len(packet.Data) - len(a.advLootPattern)
	if maxOffset < 1 {
		return nil
	}
	advLootOffset := -1
	for i := range packet.Data {
		if i > maxOffset {
			return nil
		}

		if hex.EncodeToString(packet.Data[i:i+len(a.advLootPattern)]) == hex.EncodeToString(a.advLootPattern) {
			advLootOffset = i
			break
		}
	}
	if advLootOffset == -1 {
		return nil
	}

	advloot := &AdvLoot{
		Timestamp: packet.Timestamp,
		Items:     []AdvLootItem{},
	}

	//id
	advLootOffset += 92

	advloot.ID = binary.LittleEndian.Uint16(packet.Data[advLootOffset : advLootOffset+2])
	advLootOffset += 4
	//fmt.Printf("%X\n", packet.Data[advLootOffset:advLootOffset+2])
	advloot.Count = binary.LittleEndian.Uint16(packet.Data[advLootOffset : advLootOffset+2])

	// get to mob name
	advLootOffset += 4

	tData := []byte{}
	for ; packet.Data[advLootOffset] != 0x00 && advLootOffset < len(packet.Data); advLootOffset++ {
		tData = append(tData, packet.Data[advLootOffset])
	}
	advloot.Name = fmt.Sprintf("%s", tData)
	advLootOffset++

	for i := 0; i < int(advloot.Count); i++ {
		item := AdvLootItem{}
		item.ID = binary.LittleEndian.Uint16(packet.Data[advLootOffset : advLootOffset+2])
		//fmt.Printf("id %X\n", packet.Data[advLootOffset:advLootOffset+2])
		advLootOffset += 21
		item.Count = binary.LittleEndian.Uint16(packet.Data[advLootOffset : advLootOffset+2])
		//fmt.Printf("count %X\n", packet.Data[advLootOffset:advLootOffset+2])
		advLootOffset += 4
		tData := []byte{}
		for ; packet.Data[advLootOffset] != 0x00 && advLootOffset < len(packet.Data); advLootOffset++ {
			tData = append(tData, packet.Data[advLootOffset])
		}
		item.Name = fmt.Sprintf("%s", tData)
		//fmt.Printf("name %s\n", item.Name)
		advLootOffset += 5
		advloot.Items = append(advloot.Items, item)
	}

	return advloot
}
