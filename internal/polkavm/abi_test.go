package polkavm

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_memoryMap(t *testing.T) {
	maxSize := uint32(AddressSpaceSize - uint64(VmMaxPageSize)*4)
	tests := []struct {
		expectError                                 bool
		pageSize, roDataSize, rwDataSize, stackSize uint32
		expectedRODataAddress, expectedRODataSize, expectedRWDataSize, expectedRWDataAddress,
		expectedStackSize, expectedStackAddressHigh, expectedStackAddressLow, expectedHeapBase uint32
		expectedMaxHeapSize uint64
	}{{
		pageSize: 0x4000, roDataSize: 1, rwDataSize: 1, stackSize: 1,
		expectedRODataAddress:    0x10000,
		expectedRODataSize:       0x4000,
		expectedRWDataSize:       0x4000,
		expectedStackSize:        0x4000,
		expectedRWDataAddress:    0x30000,
		expectedStackAddressHigh: 0xffff0000,
		expectedStackAddressLow:  0xfffec000,
		expectedHeapBase:         0x30001,
		expectedMaxHeapSize:      AddressSpaceSize - uint64(VmMaxPageSize)*3 - uint64(0x30001),
	}, {
		pageSize: 0x4000, roDataSize: maxSize, rwDataSize: 0, stackSize: 0,
		expectedRODataAddress:    0x10000,
		expectedRODataSize:       maxSize,
		expectedRWDataAddress:    0x10000 + VmMaxPageSize + maxSize,
		expectedRWDataSize:       0,
		expectedStackSize:        0,
		expectedStackAddressHigh: VmAddrUserStackHigh,
		expectedStackAddressLow:  VmAddrUserStackHigh,
		expectedHeapBase:         0x10000 + VmMaxPageSize + maxSize,
		expectedMaxHeapSize:      0,
	}, {
		pageSize: 0x4000, roDataSize: maxSize + 1, rwDataSize: 0, stackSize: 0,
		expectError: true,
	}, {
		pageSize: 0x4000, roDataSize: maxSize, rwDataSize: 1, stackSize: 0,
		expectError: true,
	}, {
		pageSize: 0x4000, roDataSize: maxSize, rwDataSize: 0, stackSize: 1,
		expectError: true,
	}, {
		pageSize: 0x4000, roDataSize: 0, rwDataSize: maxSize, stackSize: 0,
		expectedRODataAddress:    VmMaxPageSize,
		expectedRODataSize:       0,
		expectedRWDataAddress:    VmMaxPageSize * 2,
		expectedRWDataSize:       maxSize,
		expectedStackAddressHigh: VmAddrUserStackHigh,
		expectedStackAddressLow:  VmAddrUserStackHigh,
		expectedStackSize:        0,
		expectedHeapBase:         VmMaxPageSize*2 + maxSize,
		expectedMaxHeapSize:      0,
	}, {
		pageSize: 0x4000, roDataSize: 0, rwDataSize: 0, stackSize: maxSize,
		expectedRODataAddress:    VmMaxPageSize,
		expectedRODataSize:       0,
		expectedRWDataAddress:    VmMaxPageSize * 2,
		expectedRWDataSize:       0,
		expectedStackAddressHigh: VmAddrUserStackHigh,
		expectedStackAddressLow:  VmAddrUserStackHigh - maxSize,
		expectedStackSize:        maxSize,
		expectedHeapBase:         VmMaxPageSize * 2,
		expectedMaxHeapSize:      0,
	}}
	for _, tc := range tests {
		t.Run("", func(t *testing.T) {
			m, err := NewMemoryMap(tc.pageSize, tc.roDataSize, tc.rwDataSize, tc.stackSize, []byte{})
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

func Test_alignToNextPageUint64(t *testing.T) {
	v, _ := AlignToNextPageUint64(4096, 0)
	assert.Equal(t, uint64(0), v)
	v, _ = AlignToNextPageUint64(4096, 1)
	assert.Equal(t, uint64(4096), v)
	v, _ = AlignToNextPageUint64(4096, 4095)
	assert.Equal(t, uint64(4096), v)
	v, _ = AlignToNextPageUint64(4096, 4096)
	assert.Equal(t, uint64(4096), v)
	v, _ = AlignToNextPageUint64(4096, 4097)
	assert.Equal(t, uint64(8192), v)
	var maxVal uint64 = math.MaxUint64 + 1 - 4096
	v, _ = AlignToNextPageUint64(4096, maxVal)
	assert.Equal(t, maxVal, v)
	_, err := AlignToNextPageUint64(4096, maxVal+1)
	assert.Error(t, err)
}

func Test_alignToNextPageUint32(t *testing.T) {
	v, _ := AlignToNextPageUint32(4096, 0)
	assert.Equal(t, uint32(0), v)
	v, _ = AlignToNextPageUint32(4096, 1)
	assert.Equal(t, uint32(4096), v)
	v, _ = AlignToNextPageUint32(4096, 4095)
	assert.Equal(t, uint32(4096), v)
	v, _ = AlignToNextPageUint32(4096, 4096)
	assert.Equal(t, uint32(4096), v)
	v, _ = AlignToNextPageUint32(4096, 4097)
	assert.Equal(t, uint32(8192), v)
	var maxVal uint32 = math.MaxUint32 + 1 - 4096
	v, _ = AlignToNextPageUint32(4096, maxVal)
	assert.Equal(t, maxVal, v)
	_, err := AlignToNextPageUint32(4096, maxVal+1)
	assert.Error(t, err)
}

func Test_alignToNextPageInt(t *testing.T) {
	v, _ := AlignToNextPageInt(4096, 0)
	assert.Equal(t, 0, v)
	v, _ = AlignToNextPageInt(4096, 1)
	assert.Equal(t, 4096, v)
	v, _ = AlignToNextPageInt(4096, 4095)
	assert.Equal(t, 4096, v)
	v, _ = AlignToNextPageInt(4096, 4096)
	assert.Equal(t, 4096, v)
	v, _ = AlignToNextPageInt(4096, 4097)
	assert.Equal(t, 8192, v)
	var maxVal = math.MaxInt + 1 - 4096
	v, _ = AlignToNextPageInt(4096, maxVal)
	assert.Equal(t, maxVal, v)
	_, err := AlignToNextPageInt(4096, maxVal+1)
	assert.Error(t, err)
}
