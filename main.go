package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/xackery/eqitemsniff/analyzer"
	"github.com/xackery/eqitemsniff/gui"
)

var (
	//Version of binary
	Version string
)

func main() {
	start := time.Now()

	ctx, cancel := context.WithCancel(context.Background())

	//run program
	err := run(ctx, cancel)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("completed in %0.1f seconds\n", time.Since(start).Seconds())
}

func run(ctx context.Context, cancel context.CancelFunc) error {
	f, err := os.Create("log.txt")
	if err != nil {
		return errors.Wrap(err, "create log")
	}
	defer f.Close()

	//logger prep
	output := zerolog.ConsoleWriter{Out: f, TimeFormat: "2006-01-02 15:04:05", NoColor: true}
	if runtime.GOOS == "windows" {
		//output = zerolog.ConsoleWriter{Out: colorable.NewColorableStdout()}
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

	zerolog.SetGlobalLevel(zerolog.DebugLevel)

	log.Info().Msgf("starting eqitemsniff %s", Version)

	g, err := gui.New(ctx, cancel)
	if err != nil {
		return errors.Wrap(err, "new gui")
	}
	defer func() {
		log.Debug().Msg("cancelling from main thread")
		cancel()
		log.Debug().Msg("exiting GUI")
		g.Close()
	}()

	deviceName, err := device(ctx, g)
	if err != nil {
		return errors.Wrap(err, "device")
	}
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	g.SetStatus(fmt.Sprintf("selected %s", deviceName))

	err = capture(ctx, g, deviceName)
	if err != nil {
		return errors.Wrap(err, "capture")
	}
	log.Debug().Msg("capture finished, cleaning up")
	select {
	case <-ctx.Done():
	case <-time.After(10 * time.Second):
	}
	return nil
}

func device(ctx context.Context, g *gui.GUI) (string, error) {

	//TODO: if device already selected/passed as arg

	devs, err := pcap.FindAllDevs()
	if err != nil {
		return "", errors.Wrap(err, "pcap devlist")
	}
	i := 0

	devices := []string{}

	suggestID := -1
	for _, device := range devs {
		suggestText := ""
		ipName := ""

		if len(device.Addresses) == 0 {
			continue
		}
		for _, addr := range device.Addresses {
			ip := addr.IP.String()
			if !strings.Contains(ip, ".") {
				continue
			}
			if strings.Index(ip, "127.") == 0 {
				continue
			}
			ipName = ip
			if suggestID == -1 {
				suggestID = i
				suggestText = "(Recommended)"
			}
		}

		if len(devices) > 20 {
			continue
		}

		devices = append(devices, fmt.Sprintf("%d) %s [%s] - %s %s", i, ipName, device.Name, device.Description, suggestText))
		//log.Info().Str("name", device.Name).Str("description", device.Description).Interface("addresses", device.Addresses).Msgf("networkID: %d", i)
		i++
	}

	log.Debug().Strs("devices", devices).Msg("device list")
	deviceChan := make(chan string)
	err = g.DeviceList(devices, deviceChan)
	if err != nil {
		return "", errors.Wrap(err, "devicelist")
	}
	log.Debug().Msg("listing devices")
	deviceName := ""
	select {
	case deviceName = <-deviceChan:
	case <-ctx.Done():
		return "", nil
	}

	if strings.Contains(deviceName, "[") {
		deviceName = deviceName[strings.Index(deviceName, "[")+1:]
	}

	if strings.Contains(deviceName, "]") {
		deviceName = deviceName[:strings.Index(deviceName, "]")]
	}

	return deviceName, nil

}

func capture(ctx context.Context, g *gui.GUI, deviceName string) error {

	a, err := analyzer.New()
	if err != nil {
		return errors.Wrap(err, "failed to initialize analyzer")
	}

	captureStopChan := make(chan bool)
	err = g.StartCapture(captureStopChan)
	if err != nil {
		return errors.Wrap(err, "capture gui")
	}

	var packets []*analyzer.EQPacket

	a.GoDump = false
	a.HexDump = false

	log.Debug().Msg("pcap openlive")
	handle, err := pcap.OpenLive(deviceName, 1600, false, pcap.BlockForever)
	if err != nil {
		return errors.Wrap(err, "failed to start capture")
	}
	defer handle.Close()
	//live
	filter := "udp and (src host 69.174 or dst host 69.174)"

	//eqemu
	//filter := "udp and (src host 13.66 or dst host 13.66)"

	//filter := "udp and (src host 24.180 or dst host 24.180)"

	//filter := "udp[0:2] > 1024 and udp[2:2] > 1024 and ether proto 0x0800"

	log.Info().Msgf("capturing with filter: %s", filter)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		return errors.Wrapf(err, "bpffilter(%s):", filter)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	totalPackets := 0
	var psPacket gopacket.Packet
	for {
		select {
		case <-captureStopChan:
			return nil
		case <-ctx.Done():
			log.Debug().Msg("got exit, aborting packet capture")
			return nil
		case psPacket = <-packetSource.Packets():
		}

		packets, err = a.PacketStep1(psPacket)
		//packets, err = a.DecodePSPacket(psPacket)
		if err != nil {
			log.Warn().Err(err).Msg("process packet")
			continue
			//fmt.Printf("Src: %s:%d Dst: %s:%d Size: %d\n%s", ipv4.SrcIP.String(), udp.SrcPort, ipv4.DstIP.String(), udp.DstPort, len(data), hex.Dump(data))
			//fmt.Printf("failed to decode: %s\n", err.Error())
		}

		for _, packet := range packets {
			totalPackets++

			g.SetStatus(fmt.Sprintf("%d packets", totalPackets))
			if packet.OpCodeLabel != "Unknown" {
				log.Info().Str("opcode", packet.OpCodeLabel).Msgf(a.Dump(packet.Data))
			}

			if len(packet.Data) == 0 {
				continue
			}
			/*if len(packet.Data) == 16 {
				continue
			}
			if len(packet.Data) == 36 {
				continue
			}*/
			if len(packet.Data) < 3 {
				continue
			}

			g.AddPacket(packet)
			log.Info().Str("packet", packet.String()).Msg("got finished packet")
			log.Info().Msgf("packet dump: %s", hex.Dump(packet.Data))
		}
	}
}
