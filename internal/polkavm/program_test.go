package polkavm

import (
	"embed"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

//go:embed testdata
var fs embed.FS

func Test_ParseBlob(t *testing.T) {
	f, err := fs.Open("testdata/example-hello-world.polkavm")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pp, err := ParseBlob(NewReader(f.(io.ReadSeeker)))
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, uint32(0), pp.RODataSize)
	assert.Equal(t, uint32(0), pp.RWDataSize)
	assert.Equal(t, uint32(4096), pp.StackSize)
	assert.Equal(t, pp.JumpTableEntrySize, byte(0))
	assert.Equal(t, []byte{2, 17, 248, 3, 16, 4, 3, 21, 8, 120, 5, 78, 8, 87, 7, 1, 16, 4, 1, 21, 2, 17, 8, 19, 0}, pp.Code)
	assert.Equal(t, []byte{73, 153, 148, 254}, pp.Bitmask)
	assert.Equal(t, []byte{0, 0, 0, 0}, pp.ImportOffsets)
	assert.Equal(t, []byte{103, 101, 116, 95, 116, 104, 105, 114, 100, 95, 110, 117, 109, 98, 101, 114}, pp.ImportSymbols)
	assert.Equal(t, []byte{1, 0, 11, 97, 100, 100, 95, 110, 117, 109, 98, 101, 114, 115}, pp.Exports)
}
