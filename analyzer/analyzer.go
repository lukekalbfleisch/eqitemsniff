package analyzer

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"sort"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

const (
	// OPPrefixSixty is not yet used
	OPPrefixSixty = byte(0x60)
	// OPPrefixOversized is for fragmented packets
	OPPrefixOversized = byte(0x0d)
	// OPPrefixPacket is a complete packet in one data payload
	OPPrefixPacket = byte(0x09)
	// OPPrefixAck is a complete packet in one data payload
	OPPrefixAck = byte(0x15)
	// OPPrefixCombined is a CRC encoded packet
	OPPrefixCombined = byte(0x03)
)

// Analyzer represents an analyzer parser
type Analyzer struct {
	FragmentSize uint16
	Fragments    map[uint16]*Fragment
	Debug        bool
	GoDump       bool
	HexDump      bool
}

// Fragment is partial packets received
type Fragment struct {
	CreateDate time.Time
	Data       []byte
}

// New creates a new Analyzer
func New() (*Analyzer, error) {
	a := new(Analyzer)
	a.Fragments = map[uint16]*Fragment{}
	return a, nil
}

// Decode analyzes a packet to figure out if it is a proper EQ packet or not
func (a *Analyzer) Decode(data []byte) (packets []*EQPacket, err error) {
	var ok bool
	packets = []*EQPacket{}
	var packet *EQPacket
	prefix := data[0:2]
	data = data[2:]
	if len(data) < 4 {
		err = fmt.Errorf("packet must be at least 4 bytes, got: %d", len(data))
		return
	}
	//prefix := binary.BigEndian.Uint16(data[0:2])
	//fmt.Printf("Prefix: %#x\n", prefix)
	if prefix[0] == OPPrefixSixty {
		return
	}
	prefix2 := prefix[1]

	//buf := []byte{}
	//w := bytes.NewBuffer(buf)
	var r io.ReadCloser

	if data[0] == 0x5a { //compressed
		data = data[1:]
		r, err = zlib.NewReader(bytes.NewReader(data))
		if err != nil {
			err = errors.Wrap(err, "zlib reader")
			return
		}
		data, err = ioutil.ReadAll(r)
		if err != nil {
			err = errors.Wrap(err, "zlib enflate")
			return
		}
	} else if data[0] == 0xa5 { //uncompressed
		data = data[1:]
	}

	switch prefix2 {
	case OPPrefixSixty: //60
		//these can be ignored, for now
		return
	case OPPrefixOversized: //0d
		var sequence = binary.BigEndian.Uint16(data[0:2])
		if len(a.Fragments) == 0 {
			if len(data) < 6 {
				err = fmt.Errorf("payload should be >= 6 bytes for oversized")
				return
			}
			a.FragmentSize = binary.BigEndian.Uint16(data[0:2])
			data = data[4:]
		}
		_, ok = a.Fragments[sequence]
		if ok { //discard duplicated fragments
			return
		}
		a.Fragments[sequence] = &Fragment{
			CreateDate: time.Now(),
			Data:       data[2:],
		}
		if len(a.Fragments) >= int(a.FragmentSize) {
			packet = &EQPacket{
				OpCodeLabel: "Unknown",
			}
			//combine fragments
			data = []byte{}
			keys := []int{}
			for k := range a.Fragments {
				keys = append(keys, int(k))
			}
			sort.Ints(keys)
			for _, k := range keys {
				for _, d := range a.Fragments[uint16(k)].Data {
					data = append(data, d)
				}
			}

		}
		log.Debug().Msg("oversized")
	case OPPrefixPacket: //09
		packet, err = newPacket(data)
		if err != nil {
			return
		}
		packets = append(packets, packet)
	case OPPrefixAck: //15
		packet, err = newPacket(data)
		if err != nil {
			return
		}
		packets = append(packets, packet)
		log.Debug().Msg("ack")
	case OPPrefixCombined: //03
		data = data[:len(data)-2] //strip CRC code off tail

		combinedSize := len(data)
		log.Debug().Int("data length", len(data))
		log.Debug().Msg(hex.Dump(data))

		//pSize := binary.BigEndian.Uint16(data[0:1])

		cData := []byte{}
		for runner := 0; runner < combinedSize; {
			pSize := int(data[runner]) // binary.BigEndian.Uint16([]byte{0, data[0]}))
			log.Debug().Int("runner", runner).Int("pSize", pSize).Msg("runner")
			if pSize > len(data[runner+1:])+1 {
				//err = fmt.Errorf("runner out of bounds (runner: %d, pSize: %d)", runner, pSize)
				if len(packets) == 0 {
					err = fmt.Errorf("runner out of bounds (runner: %d, pSize: %d)", runner, pSize)
					return
				}
				return
			}
			runner++
			cData = data[runner : runner+pSize]
			log.Debug().Int("runner", runner).Int("pSize offset", runner+pSize).Str("cData", hex.Dump(cData)).Msg("")
			if len(cData) < 2 {
				err = fmt.Errorf("expected cdata to be at least 2 len, aborting")
				return
			}
			if cData[1] != OPPrefixAck {
				packet, err = newPacket(cData)
				if err != nil {
					err = errors.Wrap(err, "combiner")
					return
				}
				packets = append(packets, packet)
			}
			runner += pSize
		}
		log.Debug().Msg("combined")
	default:
		//err = fmt.Errorf("unknown prefix: %#x", prefix)
		log.Debug().Msg("unknown")
		return
	}

	return
}

// Dump will either export information as Go type data or a hex dump
func (a *Analyzer) Dump(data []byte) (output string) {
	if a.GoDump {
		output += "var data = []byte{"
		for _, d := range data {
			output += fmt.Sprintf("%#x,", d)
		}
		output += "}"
	}
	if a.HexDump {
		if len(output) > 0 {
			output += "\n"
		}
		output += hex.Dump(data)
	}
	if !a.HexDump && !a.GoDump {
		output = hex.Dump(data)
	}
	return
}

// DecodePSPacket decodes a gopacket into a set of EQ packets
func (a *Analyzer) DecodePSPacket(psPacket gopacket.Packet) (packets []*EQPacket, err error) {
	ipv4Layer := psPacket.Layer(layers.LayerTypeIPv4)
	if ipv4Layer == nil {
		err = fmt.Errorf("ipv4Layer is nil")
		return
	}
	ipv4, ok := ipv4Layer.(*layers.IPv4)
	if !ok {
		err = fmt.Errorf("ipv4 is nil")
		return
	}

	udpLayer := psPacket.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		err = fmt.Errorf("udpLayer is nil")
		return
	}
	udp, ok := udpLayer.(*layers.UDP)
	if !ok {
		err = fmt.Errorf("udp is nil")
		return
	}

	data := psPacket.ApplicationLayer().Payload()
	packets, err = a.Decode(data)
	if err != nil {
		return
	}
	for _, packet := range packets {
		packet.SourceIP = ipv4.SrcIP
		packet.SourcePort = udp.SrcPort.String()
		packet.DestinationIP = ipv4.DstIP
		packet.DestinationPort = udp.DstPort.String()
		packet.Timestamp = time.Now()
	}

	return
}
