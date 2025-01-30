package jam

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDecodeBits(t *testing.T) {
	input := []byte{17, 25, 0, 1, 2}
	expect := []bool{
		true, false, false, false, true, false, false, false,
		true, false, false, true, true, false, false, false,
		false, false, false, false, false, false, false, false,
		true, false, false, false, false, false, false, false,
		false, true, false, false, false, false, false, false,
	}
	d := NewDecoder(bytes.NewBuffer(input))

	actual := make([]bool, len(input)*8)
	if err := d.Decode(&actual); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, expect, actual)
}
