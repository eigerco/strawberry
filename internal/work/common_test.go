package work_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/eigerco/strawberry/internal/work"
)

func TestZeroPadding(t *testing.T) {
	tests := []struct {
		name           string
		input          []byte
		multiple       uint
		expectedOutput []byte
	}{
		{
			name:           "No padding",
			input:          []byte{1, 2, 3, 4},
			multiple:       4,
			expectedOutput: []byte{1, 2, 3, 4},
		},
		{
			name:           "Needs padding",
			input:          []byte{1, 2, 3, 4, 5},
			multiple:       6,
			expectedOutput: []byte{1, 2, 3, 4, 5, 0},
		},
		{
			name:           "Needs padding",
			input:          []byte("data"),
			multiple:       6,
			expectedOutput: []byte("data\x00\x00"),
		},
		{
			name:           "Padding with zero n",
			input:          []byte{1, 2, 3, 4},
			multiple:       0,
			expectedOutput: []byte{1, 2, 3, 4},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			output := work.ZeroPadding(tc.input, tc.multiple)
			assert.Equal(t, tc.expectedOutput, output)
		})
	}
}
