package jam

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodeBits(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expect   BitSequence
		len      int
		leftover int
		err      error
	}{{
		name:   "empty",
		input:  []byte{},
		len:    0,
		expect: BitSequence{},
	}, {
		name:   "1 bytes",
		input:  []byte{255},
		len:    8,
		expect: BitSequence{true, true, true, true, true, true, true, true},
	}, {
		name:  "1.5 bytes",
		input: []byte{0, 255},
		len:   12,
		expect: BitSequence{
			false, false, false, false, false, false, false, false,
			true, true, true, true,
		},
	}, {
		name:     "1 bytes 1 unused",
		input:    []byte{255, 255},
		len:      8,
		expect:   BitSequence{true, true, true, true, true, true, true, true},
		leftover: 1,
	}, {
		name:  "5 bytes",
		input: []byte{17, 25, 0, 1, 2},
		len:   5 * 8,
		expect: BitSequence{
			true, false, false, false, true, false, false, false,
			true, false, false, true, true, false, false, false,
			false, false, false, false, false, false, false, false,
			true, false, false, false, false, false, false, false,
			false, true, false, false, false, false, false, false,
		},
	}, {
		name:  "empty byte array",
		input: []byte{},
		expect: BitSequence{
			false, false, false, false, false, false, false, false,
		},
		len: 8,
		err: io.EOF,
	}, {
		name:  "not enough bytes",
		input: []byte{255},
		expect: BitSequence{
			true, true, true, true, true, true, true, true,
			false,
		},
		len: 9,
		err: io.EOF,
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buff := bytes.NewBuffer(tc.input)
			d := NewDecoder(buff)

			actual := make(BitSequence, tc.len)
			err := d.Decode(&actual)
			if tc.err != nil {
				assert.Equal(t, tc.err, err)
			}
			assert.Equal(t, tc.expect, actual)
			assert.Equal(t, tc.leftover, buff.Len())
		})
	}
}
