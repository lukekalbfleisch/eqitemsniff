package analyzer

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestZone(t *testing.T) {
	assert := assert.New(t)

	packet := &EQPacket{}
	packets := []string{
		"aa4b2c5861636b657279650000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000476661796461726b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005468652047726561746572204661796461726b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffe6e6e6e6ffffffffc8c8c8c800000020410000204100002041000020",
		"aa4b2c5861636b657279650000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000476661796461726b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005468652047726561746572204661796461726b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffe6e6e6e6ffffffffc8c8c8c800000020410000204100002041000020",
		"aa4b2c5861636b65727965000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000066656c77697468656100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004e6f72746865726e2046656c7769746865000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ff64646464828282826464646400000020410000204100002041000020",
	}
	var err error
	for _, p := range packets {
		packet.Data, err = hex.DecodeString(p)
		if !assert.NoError(err) {
			t.Fatal(err)
		}
		zone := ZoneScan(packet)
		fmt.Println(zone)
		t.Log(zone)
	}
	//t.Fatal("done")
}
