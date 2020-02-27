package gui

import (
	"fmt"
	"sort"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/xackery/eqitemsniff/analyzer"
	"github.com/xackery/eqitemsniff/scan/advloot"
	"github.com/xackery/eqitemsniff/scan/zone"
)

type packetCollection struct {
	metas []*packetMeta
}

type packetMeta struct {
	Port      string
	Zone      string
	Character string
	packets   []*packetEntry
	advloots  []*advloot.AdvLoot
}

type packetEntry struct {
	OpCode    uint16
	Count     int
	Packets   []*analyzer.EQPacket
	LastAdded time.Time
	LastSize  int
}

func (p *packetCollection) add(packet *analyzer.EQPacket) error {
	if p.metas == nil {
		p.metas = []*packetMeta{}
	}
	if packet == nil {
		return fmt.Errorf("nil packet")
	}

	z := zone.Scan(packet)
	char := fmt.Sprintf("Unknown %s", packet.ClientPort)
	zone := "Unknown"
	if z != nil {
		char = z.Character
		zone = z.Shortname
	}
	var pm *packetMeta
	for i := range p.metas {
		m := p.metas[i]
		if m.Port != packet.ClientPort {
			continue
		}
		pm = m
		if zone != "Unknown" {
			pm.Character = char
			pm.Zone = zone
			log.Debug().Msgf("got zone data for port %s", packet.ClientPort)
		}
		break
	}
	if pm == nil {
		pm = &packetMeta{
			Port:      packet.ClientPort,
			Character: char,
			Zone:      zone,
		}
		log.Debug().Msgf("added new packet meta for port %s", packet.ClientPort)
		p.metas = append(p.metas, pm)
	}

	isFound := false

	for _, pe := range pm.packets {
		if pe.OpCode != packet.OpCode {
			continue
		}
		pe.Packets = append(pe.Packets, packet)
		pe.Count = len(pe.Packets)
		pe.LastAdded = time.Now()
		pe.LastSize = len(packet.Data)
		isFound = true
		break
	}
	if !isFound {
		pe := &packetEntry{
			Count:     1,
			Packets:   []*analyzer.EQPacket{},
			OpCode:    packet.OpCode,
			LastAdded: time.Now(),
			LastSize:  len(packet.Data),
		}
		pe.Packets = append(pe.Packets, packet)
		pm.packets = append(pm.packets, pe)
	}

	sort.Sort(sort.Reverse(byTime(pm.packets)))

	advloot := advloot.Scan(packet)
	if advloot != nil {
		pm.advloots = append(pm.advloots, advloot)
	}
	return nil
}

type byTime []*packetEntry

func (s byTime) Less(i, j int) bool { return s[i].LastAdded.Before(s[j].LastAdded) }
func (s byTime) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s byTime) Len() int           { return len(s) }
