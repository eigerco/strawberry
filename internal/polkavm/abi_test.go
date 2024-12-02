package polkavm

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_memoryMap(t *testing.T) {
	maxSize := uint32(AddressSpaceSize - uint64(VmMaxPageSize)*5)
	tests := []struct {
		expectError                       bool
		roDataSize, rwDataSize, stackSize uint32
		expectedRODataAddress, expectedRODataSize, expectedRWDataSize, expectedRWDataAddress,
		expectedStackSize, expectedStackAddressHigh, expectedStackAddressLow, expectedHeapBase uint32
		expectedMaxHeapSize uint64
	}{{
		roDataSize: 1, rwDataSize: 1, stackSize: 1,
		expectedRODataAddress:    0x10000,
		expectedRODataSize:       0x1000,
		expectedRWDataSize:       0x1000,
		expectedStackSize:        0x1000,
		expectedRWDataAddress:    VmAddressSpaceBottom + 0x1000 + VmMaxPageSize,
		expectedStackAddressHigh: VmAddressSpaceTop - VmMaxPageSize,
		expectedStackAddressLow:  VmAddressSpaceTop - VmMaxPageSize - 0x1000,
		expectedHeapBase:         VmAddressSpaceBottom + 0x1000 + VmMaxPageSize + 1,
		expectedMaxHeapSize: func() uint64 {
			addressLow := VmAddressSpaceBottom + uint32(0x1000) + VmMaxPageSize + uint32(0x1000) + VmMaxPageSize
			heapSlack := uint32(0x1000) - 1
			addressHigh := VmAddressSpaceTop - VmMaxPageSize - uint32(0x1000)

			return uint64(addressHigh - addressLow + heapSlack)
		}(),
	}, {
		roDataSize: maxSize, rwDataSize: 0, stackSize: 0,
		expectedRODataAddress:    0x10000,
		expectedRODataSize:       maxSize,
		expectedRWDataAddress:    0x10000 + VmMaxPageSize + maxSize,
		expectedRWDataSize:       0,
		expectedStackAddressHigh: VmAddressSpaceTop - VmMaxPageSize,
		expectedStackAddressLow:  VmAddressSpaceTop - VmMaxPageSize,
		expectedStackSize:        0,
		expectedHeapBase:         0x10000 + VmMaxPageSize + maxSize,
		expectedMaxHeapSize:      0,
	}, {
		roDataSize: maxSize + 1, rwDataSize: 0, stackSize: 0,
		expectError: true,
	}, {
		roDataSize: maxSize, rwDataSize: 1, stackSize: 0,
		expectError: true,
	}, {
		roDataSize: maxSize, rwDataSize: 0, stackSize: 1,
		expectError: true,
	}, {
		roDataSize: 0, rwDataSize: maxSize, stackSize: 0,
		expectedRODataAddress:    VmMaxPageSize,
		expectedRODataSize:       0,
		expectedRWDataAddress:    VmMaxPageSize * 2,
		expectedRWDataSize:       maxSize,
		expectedStackAddressHigh: VmAddressSpaceTop - VmMaxPageSize,
		expectedStackAddressLow:  VmAddressSpaceTop - VmMaxPageSize,
		expectedStackSize:        0,
		expectedHeapBase:         VmMaxPageSize*2 + maxSize,
		expectedMaxHeapSize:      0,
	}, {
		roDataSize: 0, rwDataSize: 0, stackSize: maxSize,
		expectedRODataAddress:    VmMaxPageSize,
		expectedRODataSize:       0,
		expectedRWDataAddress:    VmMaxPageSize * 2,
		expectedRWDataSize:       0,
		expectedStackAddressHigh: VmAddressSpaceTop - VmMaxPageSize,
		expectedStackAddressLow:  VmAddressSpaceTop - VmMaxPageSize - maxSize,
		expectedStackSize:        maxSize,
		expectedHeapBase:         VmMaxPageSize * 2,
		expectedMaxHeapSize:      0,
	}}
	for _, tc := range tests {
		t.Run("", func(t *testing.T) {
			m, err := NewMemoryMap(tc.roDataSize, tc.rwDataSize, tc.stackSize, 0)
			if err != nil {
				if tc.expectError {
					return
				}
				t.Fatal(err)
			}
			assert.Equal(t, tc.expectedRODataAddress, m.RODataAddress)
			assert.Equal(t, tc.expectedRODataSize, m.RODataSize)
			assert.Equal(t, tc.expectedRWDataAddress, m.RWDataAddress)
			assert.Equal(t, tc.expectedStackSize, m.StackSize)
			assert.Equal(t, tc.expectedStackAddressHigh, m.StackAddressHigh)
			assert.Equal(t, tc.expectedStackAddressLow, m.StackAddressLow)
			assert.Equal(t, tc.expectedHeapBase, m.HeapBase)
			assert.Equal(t, tc.expectedMaxHeapSize, uint64(m.MaxHeapSize))
		})
	}
}

func Test_alignToNextPageUint32(t *testing.T) {
	v, _ := AlignToNextPage(0)
	assert.Equal(t, uint32(0), v)
	v, _ = AlignToNextPage(1)
	assert.Equal(t, uint32(4096), v)
	v, _ = AlignToNextPage(4095)
	assert.Equal(t, uint32(4096), v)
	v, _ = AlignToNextPage(uint32(4096))
	assert.Equal(t, uint32(4096), v)
	v, _ = AlignToNextPage(4097)
	assert.Equal(t, uint32(8192), v)
	var maxVal uint32 = math.MaxUint32 + 1 - 4096
	v, _ = AlignToNextPage(maxVal)
	assert.Equal(t, maxVal, v)
	_, err := AlignToNextPage(maxVal + 1)
	assert.Error(t, err)
}
