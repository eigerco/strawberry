package polkavm

import (
	"embed"
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
	pp, err := ParseBlob(f.(Reader))
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, pp.StackSize, uint32(4096))
	assert.Equal(t, pp.CodeAndJumpTable, []byte{0, 0, 25, 2, 17, 248, 3, 16, 4, 3, 21, 8, 120, 5, 78, 8, 87, 7, 1, 16, 4, 1, 21, 2, 17, 8, 19, 0, 73, 153, 148, 254})
	assert.Equal(t, pp.ImportOffsets, []byte{0, 0, 0, 0})
	assert.Equal(t, pp.ImportSymbols, []byte{103, 101, 116, 95, 116, 104, 105, 114, 100, 95, 110, 117, 109, 98, 101, 114})
	assert.Equal(t, pp.Exports, []byte{1, 0, 11, 97, 100, 100, 95, 110, 117, 109, 98, 101, 114, 115})
}
