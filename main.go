package main

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/mattn/go-colorable"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/xackery/eqitemsniff/analyzer"
)

var (
	//Version of binary
	Version string
)

func main() {
	start := time.Now()

	//logger prep
	output := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "2006-01-02 15:04:05"}
	if runtime.GOOS == "windows" {
		output = zerolog.ConsoleWriter{Out: colorable.NewColorableStdout()}
	}
	output.FormatLevel = func(i interface{}) string {
		return strings.ToUpper(fmt.Sprintf("%3s", i))
	}
	output.FormatMessage = func(i interface{}) string {
		return fmt.Sprintf("%s", i)
	}
	output.FormatFieldName = func(i interface{}) string {
		return fmt.Sprintf("%s: ", i)
	}
	output.FormatFieldValue = func(i interface{}) string {
		return fmt.Sprintf("%s", i)
	}
	log.Logger = zerolog.New(output).With().Timestamp().Logger()

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	//run program
	err := run()
	if err != nil {
		log.Error().Err(err).Msg("failed")
	}
	log.Info().Msgf("completed in %0.1f seconds", time.Since(start).Seconds())
}

func run() error {

	binName := "eqitemsniff"

	if runtime.GOOS == "windows" {
		binName = "eqitemsniff.exe"
	}
	usage := fmt.Sprintf("usage: %s [list | networkID] [-n]", binName)
	if len(os.Args) < 2 {
		fmt.Println(usage)
		os.Exit(1)
	}

	op := strings.ToLower(os.Args[1])
	if op == "list" {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			return errors.Wrap(err, "pcap devlist")
		}
		i := 0
		log.Info().Msg("network ID list:")
		suggestID := 0
		for _, device := range devices {
			for _, addr := range device.Addresses {
				ip := addr.IP.String()
				if !strings.Contains(ip, ".") {
					continue
				}
				if strings.Index(ip, "127.") == 0 {
					continue
				}
				suggestID = i
			}
			if len(device.Addresses) == 0 {
				continue
			}
			log.Info().Str("name", device.Name).Str("description", device.Description).Interface("addresses", device.Addresses).Msgf("networkID: %d", i)
			i++
		}
		log.Info().Msgf("recommended networkID: %d", suggestID)
		os.Exit(0)
		return nil
	}

	isNoiseMode := false
	for _, arg := range os.Args {
		if arg == "-n" {
			isNoiseMode = true
		}
	}

	networkID, err := strconv.Atoi(op)
	if err != nil {
		return errors.Wrap(err, "invalid networkID")
	}
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return errors.Wrap(err, "pcap devlist")
	}

	i := 0
	deviceName := ""
	for _, device := range devices {
		if len(device.Addresses) == 0 {
			continue
		}
		if i == networkID {
			deviceName = device.Name
		}
		i++
	}

	if err := scan(deviceName, isNoiseMode); err != nil {
		return err
	}

	fmt.Println(usage)
	os.Exit(1)
	return nil
}

func scan(deviceName string, isNoiseMode bool) error {
	var packets []*analyzer.EQPacket

	path := "noise.txt"

	ignoreOps := []int{}
	_, err := os.Stat(path)
	if err != nil {
		_, err = os.Create(path)
		if err != nil {
			return err
		}
	}
	f, err := os.Open(path)
	if err == nil {
		r := bufio.NewScanner(f)
		line := 0
		for r.Scan() {
			line++
			op, err := strconv.Atoi(r.Text())
			if err != nil {
				return errors.Wrapf(err, "line %d", line)
			}
			ignoreOps = append(ignoreOps, op)
		}
		f.Close()
	} else if err != os.ErrNotExist {
		return err
	}

	if isNoiseMode {
		f, err = os.Create(path)
		if err != nil {
			return err
		}
		defer f.Close()
		for _, op := range ignoreOps {
			_, err = f.WriteString(fmt.Sprintf("%d\n", op))
			if err != nil {
				return errors.Wrapf(err, "write %d", op)
			}
		}
	}
	a, err := analyzer.New()
	if err != nil {
		return errors.Wrap(err, "failed to initialize analyzer")
	}

	a.GoDump = false
	a.HexDump = false

	log.Debug().Msg("opening capture")
	handle, err := pcap.OpenLive(deviceName, 1600, false, pcap.BlockForever)
	if err != nil {
		return errors.Wrap(err, "failed to start capture")
	}
	defer handle.Close()

	// Set filter
	//filter := "udp and dst host " + devIP + " and src host 69.174.201.148"
	//filter := "udp and dst host 69.174.201.148 or src host 69.174.201.148"
	//filter := "udp and dst host 69.174 or src 69.174"
	filter := "udp and (src host 69.174 or dst host 69.174)"
	//filter := "udp and dst host 69.174.201.148 or src host 69.174.201.148"
	log.Info().Msgf("capturing with filter: %s", filter)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		return errors.Wrapf(err, "bpffilter(%s):", filter)
	}

	//	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &dns, &payload)

	//decodedLayers := make([]gopacket.LayerType, 0, 10)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for psPacket := range packetSource.Packets() {

		packets, err = a.DecodePSPacket(psPacket)
		if err != nil {
			log.Warn().Err(err).Msg("decodepspacket")
			//fmt.Printf("Src: %s:%d Dst: %s:%d Size: %d\n%s", ipv4.SrcIP.String(), udp.SrcPort, ipv4.DstIP.String(), udp.DstPort, len(data), hex.Dump(data))
			//fmt.Printf("failed to decode: %s\n", err.Error())
		}

		for _, packet := range packets {
			if packet.OpCodeLabel != "Unknown" {
				log.Info().Str("opcode", packet.OpCodeLabel).Msgf(a.Dump(packet.Data))
			}
			if isNoiseMode {
				isKnown := false
				for _, op := range ignoreOps {
					if op == int(packet.OpCode) {
						isKnown = true
						break
					}
				}
				if isKnown {
					continue
				}
				f.WriteString(fmt.Sprintf("%d\n", int(packet.OpCode)))
				ignoreOps = append(ignoreOps, int(packet.OpCode))
			}
			log.Info().Msg(packet.String())
			fmt.Println(a.Dump(packet.Data))
			//fmt.Printf("Src: %s:%d Dst: %s:%d Size: %d\n%s", ipv4.SrcIP.String(), udp.SrcPort, ipv4.DstIP.String(), udp.DstPort, len(data), hex.Dump(data))
			//fmt.Println("final packet", packet)

			//var adv *analyzer.AdvLoot
			//adv, err = analyzer.NewAdvLoot(packet.Data)
			//if err == nil && adv != nil { //&& packet.DestinationPort == "57889" {
			//	fmt.Println(a.Dump(packet.Data))
			//	fmt.Println(packet.DestinationPort, adv)
			//}
			//fmt.Println(i, packet, knownCode)
		}
	}
	return nil
}
