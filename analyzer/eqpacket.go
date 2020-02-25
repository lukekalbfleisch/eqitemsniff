package analyzer

import (
	"encoding/xml"
	"fmt"
	"time"
)

// EQPacket represents a completed EQ packet
type EQPacket struct {
	OpCode          uint16
	OpCodeLabel     string
	SourceIP        string
	SourcePort      string
	DestinationIP   string
	DestinationPort string
	Data            []byte
	Timestamp       time.Time
}

// SEQOPCodeXML is parsed from ShowEQ
type SEQOPCodeXML struct {
	XMLName xml.Name `xml:"seqopcodes"`
	Text    string   `xml:",chardata"`
	Opcodes []struct {
		Op      uint16
		Text    string `xml:",chardata"`
		ID      string `xml:"id,attr"`
		Name    string `xml:"name,attr"`
		Updated string `xml:"updated,attr"`
		Update  string `xml:"update,attr"`
		Comment struct {
			Text    string `xml:",chardata"`
			Payload struct {
				Text          string `xml:",chardata"`
				Dir           string `xml:"dir,attr"`
				Typename      string `xml:"typename,attr"`
				Sizechecktype string `xml:"sizechecktype,attr"`
			} `xml:"payload"`
		} `xml:"comment"`
		Payload []struct {
			Text          string `xml:",chardata"`
			Dir           string `xml:"dir,attr"`
			Typename      string `xml:"typename,attr"`
			Sizechecktype string `xml:"sizechecktype,attr"`
		} `xml:"payload"`
	} `xml:"opcode"`
}

func (packet *EQPacket) String() string {
	return fmt.Sprintf("&{OpCode: 0x%x (%s), Size: %d, Timestamp: %s, Source: %s:%s, Destination: %s:%s}", packet.OpCode, packet.OpCodeLabel, len(packet.Data), packet.Timestamp.Format(time.RFC3339), packet.SourceIP, packet.SourcePort, packet.DestinationIP, packet.DestinationPort)
}
