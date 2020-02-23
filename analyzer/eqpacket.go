package analyzer

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// EQPacket represents a completed EQ packet
type EQPacket struct {
	OpCode          uint16
	OpCodeLabel     string
	SourceIP        net.IP
	SourcePort      string
	DestinationIP   net.IP
	DestinationPort string
	Data            []byte
	Timestamp       time.Time
}

// newPacket creates a new generic EQ packet based on data provided
func newPacket(data []byte) (*EQPacket, error) {
	packet := new(EQPacket)

	if len(data) < 4 {
		return nil, fmt.Errorf("data payload < 4")
	}
	//fmt.Println(hex.Dump(data))
	offset := 0
	if data[0] == 0 {
		packet.OpCode = binary.BigEndian.Uint16(data[0:2])
		offset = 2
	} else {
		packet.OpCode = binary.BigEndian.Uint16(data[2:4])
		offset = 4
	}
	if offset > len(data) {
		return nil, fmt.Errorf("offset out of bounds")
	}
	packet.Data = data[offset:]
	return packet, nil
}

func (packet *EQPacket) String() string {
	return fmt.Sprintf("&{OpCode: %#x (%s), Size: %d, Timestamp: %s, Source: %s:%s, Destination: %s:%s}", packet.OpCode, packet.OpCodeLabel, len(packet.Data), packet.Timestamp.Format(time.RFC3339), packet.SourceIP.String(), packet.SourcePort, packet.DestinationIP.String(), packet.DestinationPort)
}
