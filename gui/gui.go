package gui

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/gdamore/tcell"
	"github.com/gdamore/tcell/encoding"
	"github.com/mattn/go-runewidth"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"github.com/xackery/eqitemsniff/analyzer"
)

// GUI represents a graphical user interface
type GUI struct {
	ctx             context.Context
	cancel          context.CancelFunc
	mutex           sync.RWMutex
	screen          tcell.Screen
	status          string
	defaultStyle    tcell.Style
	blueStyle       tcell.Style
	captureStyle    tcell.Style
	isDeviceList    bool
	deviceChan      chan string
	devices         []string
	isCaptureMode   bool
	captureStopChan chan bool
	packets         []*Packet
	packetCount     int
	eventChan       chan tcell.Event
}

type byTime []*Packet

func (s byTime) Less(i, j int) bool { return s[i].LastAdded.Before(s[j].LastAdded) }
func (s byTime) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s byTime) Len() int           { return len(s) }

// Packet displays a eqpacket
type Packet struct {
	OpCode    uint16
	Count     int
	Packets   []*analyzer.EQPacket
	LastAdded time.Time
	LastSize  int
}

// New creates a new GUI
func New(ctx context.Context, cancel context.CancelFunc) (*GUI, error) {
	g := &GUI{
		ctx:       ctx,
		cancel:    cancel,
		packets:   []*Packet{},
		eventChan: make(chan tcell.Event),
	}
	encoding.Register()
	s, err := tcell.NewScreen()
	if err != nil {
		return nil, errors.Wrap(err, "newscreen")
	}
	if err := s.Init(); err != nil {
		return nil, errors.Wrap(err, "init")
	}
	g.defaultStyle = tcell.StyleDefault.Background(tcell.ColorBlack).Foreground(tcell.ColorWhite)
	s.SetStyle(g.defaultStyle)
	s.EnableMouse()
	s.Clear()
	g.screen = s
	go g.loop()
	go g.event()
	return g, nil
}

// SetStatus sets the status text
func (g *GUI) SetStatus(status string) {
	g.mutex.Lock()
	g.status = status
	g.mutex.Unlock()
	return
}

// Clear refreshes the screen
func (g *GUI) Clear() {
	g.screen.Clear()
}

// AddPacket adds a new packet to track
func (g *GUI) AddPacket(packet *analyzer.EQPacket) {
	g.mutex.Lock()

	isFound := false
	for _, p := range g.packets {
		if p.OpCode != packet.OpCode {
			continue
		}
		p.Packets = append(p.Packets, packet)
		p.Count = len(p.Packets)
		p.LastAdded = time.Now()
		p.LastSize = len(packet.Data)
		isFound = true
		break
	}
	if !isFound {
		p := &Packet{
			Count:     1,
			Packets:   []*analyzer.EQPacket{},
			OpCode:    packet.OpCode,
			LastAdded: time.Now(),
			LastSize:  len(packet.Data),
		}
		p.Packets = append(p.Packets, packet)
		g.packets = append(g.packets, p)
	}
	sort.Sort(sort.Reverse(byTime(g.packets)))

	g.mutex.Unlock()
}

// DeviceList prompts a user for which device to choose
func (g *GUI) DeviceList(devices []string, deviceChan chan string) error {
	if g.isDeviceList {
		return fmt.Errorf("device list already set")
	}

	g.mutex.Lock()
	g.isDeviceList = true
	g.deviceChan = deviceChan
	g.devices = devices
	g.mutex.Unlock()
	log.Debug().Msgf("got %d devices", len(g.devices))
	return nil
}

// StartCapture begins the capturing UI
func (g *GUI) StartCapture(captureStopChan chan bool) error {
	g.mutex.Lock()
	g.isCaptureMode = true
	g.captureStopChan = captureStopChan
	g.status = "started capture"
	g.mutex.Unlock()
	return nil
}

// Close exits the gui
func (g *GUI) Close() {
	g.screen.Fini()
}

func (g *GUI) event() {
	s := g.screen
	for {
		ev := s.PollEvent()
		select {
		case g.eventChan <- ev:
		case <-g.ctx.Done():
			return
		}
	}
}

func (g *GUI) loop() {
	s := g.screen
	posfmt := "Mouse: %d, %d  "
	btnfmt := "Buttons: %s"
	keyfmt := "Keys: %s"
	g.blueStyle = tcell.StyleDefault.Foreground(tcell.ColorWhite).Background(tcell.ColorDarkBlue)
	g.captureStyle = tcell.StyleDefault.Foreground(tcell.ColorWhite).Background(tcell.ColorDarkRed)

	mx, my := -1, -1
	w, h := s.Size()
	bstr := ""
	lks := ""
	ecnt := 0

	for {
		g.mutex.RLock()

		bstr = ""

		st := tcell.StyleDefault.Background(tcell.ColorRed)
		w, h = s.Size()

		if !g.isDeviceList {
			s := g.screen
			w, h := s.Size()

			drawBox(s, 36, 1, w-1, h-2, g.blueStyle, ' ')
			emitStr(s, 37, 2, g.blueStyle, "Select which device to listen to")

			for i, device := range g.devices {
				emitStr(s, 37, i+4, g.blueStyle, device)
			}
		}

		statusHeight := 6

		if g.isCaptureMode {
			drawBox(s, 36, 1, w-1, h-2, g.captureStyle, ' ')
			emitStr(s, 37, 2, g.captureStyle, "Capturing...")
			i := 0
			for _, packet := range g.packets {
				emitStr(s, 37, i+3, g.captureStyle, fmt.Sprintf("0x%x %d [%d bytes]", packet.OpCode, len(packet.Packets), packet.LastSize))
				i++
				if i > h-6 {
					break
				}
			}

			statusHeight = h - 2
		}

		drawBox(s, 1, 1, 35, statusHeight, g.blueStyle, ' ')
		emitStr(s, 2, 2, g.blueStyle, "Press ESC twice to exit")
		emitStr(s, 2, 3, g.blueStyle, fmt.Sprintf(posfmt, mx, my))
		emitStr(s, 2, 4, g.blueStyle, fmt.Sprintf(btnfmt, bstr))
		emitStr(s, 2, 5, g.blueStyle, fmt.Sprintf(keyfmt, lks))

		g.drawStatusBar(g.blueStyle)

		s.Show()
		g.mutex.RUnlock()

		select {
		case <-g.ctx.Done():
			return
		case ev := <-g.eventChan:
			switch ev := ev.(type) {
			case *tcell.EventResize:
				s.Sync()
				s.SetContent(w-1, h-1, 'R', nil, st)
			case *tcell.EventKey:
				s.SetContent(w-2, h-2, ev.Rune(), nil, st)
				s.SetContent(w-1, h-1, 'K', nil, st)
				if ev.Key() == tcell.KeyEscape {
					ecnt++
					g.mutex.Lock()
					g.status = "escape pressed, press again to exit"
					g.mutex.Unlock()
					log.Debug().Msgf("escape pressed %d times", ecnt)
					if ecnt > 1 {
						g.status = "exiting..."
						g.cancel()
						log.Info().Msg("exiting via escape sequence")
						return
					}
				} else if ev.Key() == tcell.KeyCtrlL {
					s.Sync()
				} else {
					ecnt = 0
					if ev.Rune() == 'C' || ev.Rune() == 'c' {
						s.Clear()
					}
				}
				lks = ev.Name()
				if g.isDeviceList {
					for i, dev := range g.devices {
						if ev.Name() == fmt.Sprintf("Rune[%d]", i) {
							select {
							case g.deviceChan <- dev:
								g.mutex.Lock()
								g.isDeviceList = false
								s.Clear()
								g.mutex.Unlock()
							case <-time.After(1 * time.Second):
							case <-g.ctx.Done():
								return
							}
							break
						}
					}
				}
			case *tcell.EventMouse:
				x, y := ev.Position()
				button := ev.Buttons()
				for i := uint(0); i < 8; i++ {
					if int(button)&(1<<i) != 0 {
						bstr += fmt.Sprintf(" Button%d", i+1)
					}
				}
				if button&tcell.WheelUp != 0 {
					bstr += " WheelUp"
				}
				if button&tcell.WheelDown != 0 {
					bstr += " WheelDown"
				}
				if button&tcell.WheelLeft != 0 {
					bstr += " WheelLeft"
				}
				if button&tcell.WheelRight != 0 {
					bstr += " WheelRight"
				}
				// Only buttons, not wheel events
				button &= tcell.ButtonMask(0xff)

				switch ev.Buttons() {
				case tcell.ButtonNone:
				case tcell.Button1:
					if g.isDeviceList && x >= 37 && y > 3 && x < w-1 && y-4 < len(g.devices) {
						dev := g.devices[y-4]
						select {
						case g.deviceChan <- dev:
							g.mutex.Lock()
							g.isDeviceList = false
							s.Clear()
							g.mutex.Unlock()
						case <-time.After(1 * time.Second):
						case <-g.ctx.Done():
							return
						}
						break
					}
				case tcell.Button2:
				case tcell.Button3:
				case tcell.Button4:
				case tcell.Button5:
				case tcell.Button6:
				case tcell.Button7:
				case tcell.Button8:
				default:

				}
				s.SetContent(w-1, h-1, 'M', nil, st)
				mx, my = x, y
			default:
				s.SetContent(w-1, h-1, 'X', nil, st)
			}
		default:
		}
	}
}

func emitStr(s tcell.Screen, x, y int, style tcell.Style, str string) {
	for _, c := range str {
		var comb []rune
		w := runewidth.RuneWidth(c)
		if w == 0 {
			comb = []rune{c}
			c = ' '
			w = 1
		}
		s.SetContent(x, y, c, comb, style)
		x += w
	}
}

func drawBox(s tcell.Screen, x1, y1, x2, y2 int, style tcell.Style, r rune) {
	if y2 < y1 {
		y1, y2 = y2, y1
	}
	if x2 < x1 {
		x1, x2 = x2, x1
	}

	for col := x1; col <= x2; col++ {
		s.SetContent(col, y1, tcell.RuneHLine, nil, style)
		s.SetContent(col, y2, tcell.RuneHLine, nil, style)
	}
	for row := y1 + 1; row < y2; row++ {
		s.SetContent(x1, row, tcell.RuneVLine, nil, style)
		s.SetContent(x2, row, tcell.RuneVLine, nil, style)
	}
	if y1 != y2 && x1 != x2 {
		// Only add corners if we need to
		s.SetContent(x1, y1, tcell.RuneULCorner, nil, style)
		s.SetContent(x2, y1, tcell.RuneURCorner, nil, style)
		s.SetContent(x1, y2, tcell.RuneLLCorner, nil, style)
		s.SetContent(x2, y2, tcell.RuneLRCorner, nil, style)
	}
	for row := y1 + 1; row < y2; row++ {
		for col := x1 + 1; col < x2; col++ {
			s.SetContent(col, row, r, nil, style)
		}
	}
}

func (g *GUI) drawStatusBar(style tcell.Style) {
	status := g.status
	s := g.screen
	w, h := s.Size()
	for x := 0; x < w; x++ {
		s.SetContent(x, h-1, ' ', nil, style)
	}
	emitStr(s, 1, h-1, style, status)
}
