package analyzer

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

const (
	// OPSessionRequest for session starts
	OPSessionRequest = byte(0x01)

	// OPSessionResponse packet
	OPSessionResponse = byte(0x02)
	// OPCombined packet
	OPCombined = byte(0x03)
	// OPSessionDisconnect packet
	OPSessionDisconnect = byte(0x05)
	// OPKeepAlive packet
	OPKeepAlive = byte(0x06)
	// OPSessionStatRequest packet
	OPSessionStatRequest = byte(0x07)
	// OPSessionStatResponse packet
	OPSessionStatResponse = byte(0x08)
	// OPPacket packet
	OPPacket = byte(0x09)
	// OPOversized packet
	OPOversized = byte(0x0d)
	// OPAckFuture packet
	OPAckFuture = byte(0x11)
	// OPAck packet
	OPAck = byte(0x15)
	// OPAppCombined packet
	OPAppCombined = byte(0x19)
	// OPAckAfterDisconnect packet
	OPAckAfterDisconnect = byte(0x1d)
	// OPSixty packet
	OPSixty = byte(0x60)
)

// Analyzer represents an analyzer parser
type Analyzer struct {
	FragmentSize    uint16
	FragmentMaxSize uint32
	Fragments       map[uint16][]byte
	Debug           bool
	GoDump          bool
	HexDump         bool
	OpCodes         []*SEQOPCodeXML
	advLootPattern  []byte
}

// Fragment is partial packets received
type Fragment struct {
	CreateDate time.Time
	Data       []byte
}

// New creates a new Analyzer
func New() (*Analyzer, error) {
	var err error
	a := new(Analyzer)
	a.advLootPattern, err = hex.DecodeString("42c07003000000c4d8a7008d940400cb29")
	if err != nil {
		return nil, errors.Wrap(err, "advlootpattern decode")
	}

	a.Fragments = map[uint16][]byte{}

	log.Debug().Msg("scan for xml")
	err = filepath.Walk(".", func(path string, fi os.FileInfo, err error) error {
		if fi == nil {
			return nil
		}
		if fi.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".xml" {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		dec := xml.NewDecoder(f)
		seq := new(SEQOPCodeXML)
		err = dec.Decode(seq)
		if err != nil {
			log.Warn().Err(errors.Wrapf(err, "decode %s", path)).Msg("failed to parse xml")
			return nil
		}

		a.OpCodes = append(a.OpCodes, seq)
		return nil
	})
	log.Debug().Msgf("found %d xml opcodes", len(a.OpCodes))

	if err != nil {
		return nil, errors.Wrap(err, "walk")
	}
	return a, nil
}

// PacketStep1 begins processing a packet
// step1: break down dst/src, figure out if compressed
func (a *Analyzer) PacketStep1(psPacket gopacket.Packet) ([]*EQPacket, error) {
	var err error

	ipv4Layer := psPacket.Layer(layers.LayerTypeIPv4)
	if ipv4Layer == nil {
		return nil, fmt.Errorf("ipv4Layer is nil")
	}
	ipv4, ok := ipv4Layer.(*layers.IPv4)
	if !ok {
		return nil, fmt.Errorf("ipv4 is nil")
	}

	//emu
	// != "13.66.207.54"
	if ipv4.DstIP.String() != "10.0.0.10" && !strings.Contains(ipv4.SrcIP.String(), "69") {
		return nil, fmt.Errorf("invalid src/dst")
	}

	data := psPacket.ApplicationLayer().Payload()

	var r io.ReadCloser

	//log.Debug().Str("prefix?", hex.Dump(data[0:4])).Msg("prefix analyze")

	//figure out compression
	//log.Debug().Msgf("raw before caress %s", hex.Dump(data))

	if data[2] == 0x5a { //compressed
		data = data[3:]
		r, err = zlib.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, errors.Wrap(err, "zlib reader")
		}
		data, err = ioutil.ReadAll(r)
		if err != nil {
			return nil, errors.Wrap(err, "zlib enflate")
		}
		log.Debug().Msgf("decompressed, length: %d", len(data[2:]))
	} else if data[2] == 0xa5 { //uncompressed
		data = data[3:]
		log.Debug().Msgf("already uncompressed length: %d", len(data[2:]))
	} else {
		log.Debug().Msgf("packet is neither compressed or uncompressed? length: %d", len(data[2:]))
		data = data[3:]
	}

	//shave first two bytes off?
	data = data[1:]
	log.Debug().Msgf("raw after caress %s", hex.Dump(data))

	if len(data) < 4 {
		return nil, fmt.Errorf("datatoo small")
	}
	packets, err := a.packetStep2(data[0:2], data[2:], psPacket)
	if err != nil {
		return nil, errors.Wrap(err, "step2")
	}
	return packets, err
}

// packetStep2 begins analyzing prefix and packet ordering
func (a *Analyzer) packetStep2(prefix []byte, data []byte, psPacket gopacket.Packet) ([]*EQPacket, error) {
	var err error
	if len(prefix) != 2 {
		return nil, fmt.Errorf("prefix is too small at %d", len(prefix))
	}

	var packet *EQPacket

	if prefix[0] == OPSixty {
		return []*EQPacket{}, nil
	}

	log.Debug().Msgf("processpacket prefix %s", hex.Dump(prefix))

	switch prefix[1] {
	case OPKeepAlive: //06
		packet, err = a.packetStep3(data, psPacket)
		if err != nil {
			return nil, errors.Wrap(err, "keepalive step3")
		}
		return []*EQPacket{packet}, nil
	case OPSixty: //60
		//these can be ignored, for now
		return []*EQPacket{}, nil
	case OPOversized: //0d
		//get sequence
		var sequence = binary.LittleEndian.Uint16(data[0:2])
		//cut the sequence
		data = data[2:]

		//if we have no fragments, get the size
		if len(a.Fragments) == 0 {
			if len(data) < 6 {
				return nil, fmt.Errorf("payload should be >= 6 bytes for oversized")
			}

			a.FragmentMaxSize = binary.LittleEndian.Uint32(data[0:4])
			data = data[4:]
		}

		a.Fragments[sequence] = data

		a.FragmentSize += uint16(len(data))

		if uint32(a.FragmentSize) < a.FragmentMaxSize {
			return []*EQPacket{}, nil
		}
		//we have it all. Combine
		data = []byte{}

		keys := make([]int, 0, len(a.Fragments))
		for k := range a.Fragments {
			keys = append(keys, int(k))
		}
		sort.Ints(keys)

		for _, k := range keys {
			for _, frag := range a.Fragments[uint16(k)] {
				data = append(data, frag)
			}
		}

		packet, err = a.packetStep3(data, psPacket)
		if err != nil {
			return nil, errors.Wrap(err, "step3 oversized fragment")
		}
		return []*EQPacket{packet}, nil
	case OPPacket: //09
		data = data[2:] // remove op prefix
		packet, err = a.packetStep3(data, psPacket)
		if err != nil {
			return nil, errors.Wrap(err, "step3 packet")
		}
		return []*EQPacket{packet}, nil
	case OPAck: //15
		packet, err = a.packetStep3(data, psPacket)
		if err != nil {
			return nil, errors.Wrap(err, "step3 ack")
		}
		return []*EQPacket{packet}, nil
	case OPCombined: //03 crc packet
		if len(data) < 2 {
			return nil, fmt.Errorf("03 packet with less than 2 bytes")
		}
		data = data[:len(data)-2] //strip CRC code off tail

		combinedSize := len(data)
		log.Debug().Int("combined size:", len(data)).Msg("combining packets")

		//pSize := binary.BigEndian.Uint16(data[0:1])

		packets := []*EQPacket{}
		cData := []byte{}
		for runner := 0; runner < combinedSize; {

			pSize := int(data[runner]) // binary.BigEndian.Uint16([]byte{0, data[0]}))
			log.Debug().Int("runner", runner).Int("pSize", pSize).Msg("runner")

			if pSize > len(data[runner+1:])+1 {
				if len(packets) == 0 {
					return nil, fmt.Errorf("runner out of bounds (runner: %d, pSize: %d)", runner, pSize)
				}
				return packets, nil
			}
			runner++

			cData = data[runner : runner+pSize]

			//log.Debug().Int("runner", runner).Int("pSize offset", runner+pSize).Str("cData", hex.Dump(cData)).Msg("")
			if len(cData) < 2 {
				return nil, fmt.Errorf("expected cdata to be at least 2 len, aborting")
			}
			if cData[1] != OPAck {
				packets, err = a.packetStep2(data[0:2], data[2:], psPacket)
				if err != nil {
					return nil, errors.Wrap(err, "step2 combine ack")
				}
			}
			runner += pSize
		}
		return packets, nil
	default:
		log.Debug().Msgf("unhandled opcode prefix %s, fallback to %s", hex.Dump(prefix), hex.Dump(data))
		packet, err = a.packetStep3(data, psPacket)
		if err != nil {
			return nil, errors.Wrap(err, "step3 default")
		}
		return []*EQPacket{packet}, nil
		//err = fmt.Errorf("unknown prefix: %#x", prefix)
		//val := binary.LittleEndian.Uint16(data[0:2])

		//log.Debug().Str("prefix", hex.Dump(data)).Str("data", hex.Dump(data[2:])).Msgf("ignoring prefix 0x%x", val)
	}
}

// packetStep3 extracts opcode and creates a generic EQPacket
func (a *Analyzer) packetStep3(data []byte, psPacket gopacket.Packet) (*EQPacket, error) {
	packet := new(EQPacket)

	if len(data) < 4 {
		return nil, fmt.Errorf("data payload < 4")
	}
	//log.Debug().Msg(hex.Dump(data))

	packet.OpCode = binary.LittleEndian.Uint16(data[0:2])

	ipv4Layer := psPacket.Layer(layers.LayerTypeIPv4)
	if ipv4Layer == nil {
		return nil, fmt.Errorf("ipv4Layer is nil")
	}
	ipv4, ok := ipv4Layer.(*layers.IPv4)
	if !ok {
		return nil, fmt.Errorf("ipv4 is nil")
	}

	packet.SourceIP = ipv4.SrcIP.String()
	packet.DestinationIP = ipv4.DstIP.String()
	packet.Timestamp = psPacket.Metadata().Timestamp
	offset := 2
	/*
		if data[0] == 0 {
			packet.OpCode = binary.LittleEndian.Uint16(data[0:2])
			offset = 2
		} else {
			packet.OpCode = binary.LittleEndian.Uint16(data[2:4])
			offset = 4
		}
	*/
	if offset > len(data) {
		return nil, fmt.Errorf("offset out of bounds")
	}

	//log.Debug().Str("data", hex.Dump(data)).Str("guess", hex.Dump(data[0:2])).Msgf("decipher opcode 0%x", packet.OpCode)
	packet.Data = data[offset:]

	for _, seq := range a.OpCodes {
		for _, op := range seq.Opcodes {
			if op.ID != fmt.Sprintf("0x%x", packet.OpCode) {
				continue
			}
			packet.OpCodeLabel = op.Name
			log.Debug().Msgf("found opcode!!! %s", packet.OpCodeLabel)
		}
	}

	log.Debug().Str("opcode1", hex.Dump(data[0:2])).Str("opcode2", hex.Dump(data[2:4])).Int("offset", offset).Msgf("opcode1g 0x%x opcode2g 0x%x", packet.OpCode, binary.BigEndian.Uint16(data[2:4]))

	return packet, nil
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
