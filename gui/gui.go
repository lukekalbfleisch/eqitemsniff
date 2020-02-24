package gui

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/gdamore/tcell"
	"github.com/gdamore/tcell/encoding"
	"github.com/mattn/go-runewidth"
	"github.com/pkg/errors"
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
	isDeviceList    bool
	deviceChan      chan string
	devices         []string
	isCaptureMode   bool
	captureStopChan chan bool
	packets         map[uint16][]*analyzer.EQPacket
	packetCount     int
}

// New creates a new GUI
func New(ctx context.Context, cancel context.CancelFunc) (*GUI, error) {
	g := &GUI{
		ctx:     ctx,
		cancel:  cancel,
		packets: make(map[uint16][]*analyzer.EQPacket),
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
	if g.packets[packet.OpCode] == nil {
		g.packets[packet.OpCode] = []*analyzer.EQPacket{}
	}
	g.packets[packet.OpCode] = append(g.packets[packet.OpCode], packet)
	g.packetCount++
	g.status = fmt.Sprintf("packet total: %d", g.packetCount)
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

func (g *GUI) loop() {
	s := g.screen
	posfmt := "Mouse: %d, %d  "
	btnfmt := "Buttons: %s"
	keyfmt := "Keys: %s"
	white := tcell.StyleDefault.Foreground(tcell.ColorWhite).Background(tcell.ColorDarkBlue)
	captureStyle := tcell.StyleDefault.Foreground(tcell.ColorWhite).Background(tcell.ColorDarkRed)

	mx, my := -1, -1
	w, h := s.Size()
	bstr := ""
	lks := ""
	ecnt := 0

	for {
		select {
		case <-g.ctx.Done():
			return
		default:
		}
		g.mutex.RLock()

		g.drawStatusBar(white)

		if g.isDeviceList {
			drawBox(s, 36, 1, w-1, h-2, white, ' ')
			emitStr(s, 37, 2, white, "Select which device to listen to")

			for i, device := range g.devices {
				emitStr(s, 37, i+4, white, device)
			}
		}

		statusHeight := 6
		if g.isCaptureMode {
			drawBox(s, 36, 1, w-1, h-2, captureStyle, ' ')
			emitStr(s, 37, 2, captureStyle, "Capturing...")
			i := 0
			for op, packets := range g.packets {
				emitStr(s, 37, i+3, captureStyle, fmt.Sprintf("0x%x %d", op, len(packets)))
				i++
				if i > 20 {
					break
				}
			}
			statusHeight = h - 2
		}

		drawBox(s, 1, 1, 35, statusHeight, white, ' ')
		emitStr(s, 2, 2, white, "Press ESC twice to exit")
		emitStr(s, 2, 3, white, fmt.Sprintf(posfmt, mx, my))
		emitStr(s, 2, 4, white, fmt.Sprintf(btnfmt, bstr))
		emitStr(s, 2, 5, white, fmt.Sprintf(keyfmt, lks))

		s.Show()
		bstr = ""
		ev := s.PollEvent()
		st := tcell.StyleDefault.Background(tcell.ColorRed)
		w, h = s.Size()

		switch ev := ev.(type) {
		case *tcell.EventResize:
			s.Sync()
			s.SetContent(w-1, h-1, 'R', nil, st)
		case *tcell.EventKey:
			s.SetContent(w-2, h-2, ev.Rune(), nil, st)
			s.SetContent(w-1, h-1, 'K', nil, st)
			if ev.Key() == tcell.KeyEscape {
				ecnt++
				g.status = "escape pressed once"
				if ecnt > 1 {
					g.cancel()
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
							g.mutex.RUnlock()
							g.mutex.Lock()
							g.isDeviceList = false
							s.Clear()
							g.mutex.Unlock()
							g.mutex.RLock()
						case <-time.After(1 * time.Second):
						case <-g.ctx.Done():
							g.mutex.RUnlock()
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
						g.mutex.RUnlock()
						g.mutex.Lock()
						g.isDeviceList = false
						s.Clear()
						g.mutex.Unlock()
						g.mutex.RLock()
					case <-time.After(1 * time.Second):
					case <-g.ctx.Done():
						g.mutex.RUnlock()
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
		g.mutex.RUnlock()
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
