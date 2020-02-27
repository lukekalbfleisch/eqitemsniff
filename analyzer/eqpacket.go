package analyzer

import (
	"encoding/xml"
	"fmt"
	"net"
	"time"
)

var privateIPBlocks []*net.IPNet

// EQPacket represents a completed EQ packet
type EQPacket struct {
	OpCode        uint16
	OpCodeLabel   string
	SourceIP      net.IP
	ClientPort    string
	DestinationIP net.IP
	Data          []byte
	Timestamp     time.Time
}

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("parse error on %q: %v", cidr, err))
		}
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

// IsFromServer returns true if dstIP is a private ip address
func (packet *EQPacket) IsFromServer() bool {
	ip := packet.DestinationIP
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
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
	return ""
	//return fmt.Sprintf("&{OpCode: 0x%x (%s), Size: %d, Timestamp: %s, Source: %s:%s, Destination: %s:%s}", packet.OpCode, packet.OpCodeLabel, len(packet.Data), packet.Timestamp.Format(time.RFC3339), packet.SourceIP, packet.SourcePort, packet.DestinationIP, packet.DestinationPort)
}
