package jam

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodeBits(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expect   BitSequence
		leftover int
		err      error
	}{{
		name:   "empty",
		input:  []byte{},
		expect: BitSequence{},
	}, {
		name:   "1 bytes",
		input:  []byte{255},
		expect: BitSequence{true, true, true, true, true, true, true, true},
	}, {
		name:  "1.5 bytes",
		input: []byte{0, 255},
		expect: BitSequence{
			false, false, false, false, false, false, false, false,
			true, true, true, true, true, true, true, true,
		},
	}, {
		name:  "5 bytes",
		input: []byte{17, 25, 0, 1, 2},
		expect: BitSequence{
			true, false, false, false, true, false, false, false,
			true, false, false, true, true, false, false, false,
			false, false, false, false, false, false, false, false,
			true, false, false, false, false, false, false, false,
			false, true, false, false, false, false, false, false,
		},
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buff := bytes.NewBuffer(tc.input)
			d := NewDecoder(buff)

			actual := BitSequence{}
			err := d.DecodeFixedLength(&actual, uint(len(tc.input)))
			if tc.err != nil {
				assert.Equal(t, tc.err, err)
			}

			assert.Equal(t, tc.expect, actual)
			assert.Equal(t, tc.leftover, buff.Len())
		})
	}
}
