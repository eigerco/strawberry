package safemath

import (
	"math"
	"testing"
)

func TestAdd_int64(t *testing.T) {
	tests := []struct {
		name    string
		a, b    int64
		want    int64
		wantErr bool
	}{
		// Basic cases
		{"zero plus zero", 0, 0, 0, false},
		{"zero plus positive", 0, 5, 5, false},
		{"positive plus zero", 5, 0, 5, false},
		{"zero plus negative", 0, -5, -5, false},
		{"negative plus zero", -5, 0, -5, false},

		// Positive + Positive
		{"small positives", 1, 2, 3, false},
		{"larger positives", 100, 200, 300, false},
		{"positive near max", math.MaxInt64 - 10, 5, math.MaxInt64 - 5, false},
		{"positive at boundary", math.MaxInt64 - 1, 1, math.MaxInt64, false},

		// Negative + Negative
		{"small negatives", -1, -2, -3, false},
		{"larger negatives", -100, -200, -300, false},
		{"negative near min", math.MinInt64 + 10, -5, math.MinInt64 + 5, false},
		{"negative at boundary", math.MinInt64 + 1, -1, math.MinInt64, false},

		// Positive + Negative (no overflow possible)
		{"positive plus negative to positive", 10, -3, 7, false},
		{"positive plus negative to negative", 3, -10, -7, false},
		{"positive plus negative to zero", 5, -5, 0, false},
		{"max plus min plus one", math.MaxInt64, math.MinInt64 + 1, 0, false},
		{"max plus negative one", math.MaxInt64, -1, math.MaxInt64 - 1, false},
		{"min plus positive one", math.MinInt64, 1, math.MinInt64 + 1, false},

		// Overflow cases - positive overflow
		{"overflow max plus one", math.MaxInt64, 1, 0, true},
		{"overflow max plus max", math.MaxInt64, math.MaxInt64, 0, true},
		{"overflow large positives", math.MaxInt64 - 5, 10, 0, true},
		{"overflow half max doubled", math.MaxInt64/2 + 1, math.MaxInt64/2 + 1, 0, true},

		// Overflow cases - negative overflow
		{"overflow min minus one", math.MinInt64, -1, 0, true},
		{"overflow min plus min", math.MinInt64, math.MinInt64, 0, true},
		{"overflow large negatives", math.MinInt64 + 5, -10, 0, true},
		{"overflow half min doubled", math.MinInt64/2 - 1, math.MinInt64/2 - 1, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Add(tt.a, tt.b)
			if ok == tt.wantErr {
				t.Errorf("Add(%d, %d) ok = %v, wantErr %v", tt.a, tt.b, ok, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Add(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestAdd_int32(t *testing.T) {
	tests := []struct {
		name    string
		a, b    int32
		want    int32
		wantErr bool
	}{
		{"zero plus zero", 0, 0, 0, false},
		{"small positives", 1, 2, 3, false},
		{"max boundary", math.MaxInt32 - 1, 1, math.MaxInt32, false},
		{"min boundary", math.MinInt32 + 1, -1, math.MinInt32, false},
		{"overflow positive", math.MaxInt32, 1, 0, true},
		{"overflow negative", math.MinInt32, -1, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Add(tt.a, tt.b)
			if ok == tt.wantErr {
				t.Errorf("Add(%d, %d) ok = %v, wantErr %v", tt.a, tt.b, ok, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Add(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestAdd_int16(t *testing.T) {
	tests := []struct {
		name    string
		a, b    int16
		want    int16
		wantErr bool
	}{
		{"zero plus zero", 0, 0, 0, false},
		{"small positives", 1, 2, 3, false},
		{"larger positives", 100, 200, 300, false},
		{"max boundary", math.MaxInt16 - 1, 1, math.MaxInt16, false},
		{"min boundary", math.MinInt16 + 1, -1, math.MinInt16, false},
		{"mixed signs", 100, -50, 50, false},
		{"overflow positive", math.MaxInt16, 1, 0, true},
		{"overflow negative", math.MinInt16, -1, 0, true},
		{"overflow large positives", math.MaxInt16 - 5, 10, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Add(tt.a, tt.b)
			if ok == tt.wantErr {
				t.Errorf("Add(%d, %d) ok = %v, wantErr %v", tt.a, tt.b, ok, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Add(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestAdd_int8(t *testing.T) {
	tests := []struct {
		name    string
		a, b    int8
		want    int8
		wantErr bool
	}{
		{"zero plus zero", 0, 0, 0, false},
		{"small positives", 1, 2, 3, false},
		{"max boundary", math.MaxInt8 - 1, 1, math.MaxInt8, false},
		{"min boundary", math.MinInt8 + 1, -1, math.MinInt8, false},
		{"mixed signs", 50, -30, 20, false},
		{"overflow positive", math.MaxInt8, 1, 0, true},
		{"overflow negative", math.MinInt8, -1, 0, true},
		{"overflow large positives", math.MaxInt8 - 5, 10, 0, true},
		{"overflow large negatives", math.MinInt8 + 5, -10, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Add(tt.a, tt.b)
			if ok == tt.wantErr {
				t.Errorf("Add(%d, %d) ok = %v, wantErr %v", tt.a, tt.b, ok, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Add(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestSub_int64(t *testing.T) {
	tests := []struct {
		name    string
		a, b    int64
		want    int64
		wantErr bool
	}{
		// Basic cases
		{"zero minus zero", 0, 0, 0, false},
		{"zero minus positive", 0, 5, -5, false},
		{"positive minus zero", 5, 0, 5, false},
		{"zero minus negative", 0, -5, 5, false},
		{"negative minus zero", -5, 0, -5, false},

		// Positive - Positive
		{"small positives same", 5, 5, 0, false},
		{"small positives diff", 10, 3, 7, false},
		{"positive result negative", 3, 10, -7, false},
		{"max minus itself", math.MaxInt64, math.MaxInt64, 0, false},
		{"max minus one", math.MaxInt64, 1, math.MaxInt64 - 1, false},

		// Negative - Negative
		{"small negatives same", -5, -5, 0, false},
		{"small negatives diff", -3, -10, 7, false},
		{"negative result more negative", -10, -3, -7, false},
		{"min minus itself", math.MinInt64, math.MinInt64, 0, false},
		{"min minus neg one", math.MinInt64, -1, math.MinInt64 + 1, false},

		// Positive - Negative (can overflow positive)
		{"positive minus negative small", 5, -3, 8, false},
		{"max minus negative one", math.MaxInt64, -1, 0, true},
		{"large positive minus large negative", math.MaxInt64 - 5, -10, 0, true},

		// Negative - Positive (can overflow negative)
		{"negative minus positive small", -5, 3, -8, false},
		{"min minus positive one", math.MinInt64, 1, 0, true},
		{"large negative minus large positive", math.MinInt64 + 5, 10, 0, true},

		// Edge cases
		{"one minus max", 1, math.MaxInt64, math.MinInt64 + 2, false},
		{"neg one minus min", -1, math.MinInt64, math.MaxInt64, false},
		{"min minus max", math.MinInt64, math.MaxInt64, 0, true},
		{"max minus min", math.MaxInt64, math.MinInt64, 0, true},
		{"zero minus min overflow", 0, math.MinInt64, 0, true},
		{"max minus negative max overflow", math.MaxInt64, -math.MaxInt64, 0, true},

		// Near boundary - no overflow
		{"near max no overflow", math.MaxInt64 - 10, -5, math.MaxInt64 - 5, false},
		{"near min no overflow", math.MinInt64 + 10, 5, math.MinInt64 + 5, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Sub(tt.a, tt.b)
			if ok == tt.wantErr {
				t.Errorf("Sub(%d, %d) ok = %v, wantErr %v", tt.a, tt.b, ok, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Sub(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestSub_int32(t *testing.T) {
	tests := []struct {
		name    string
		a, b    int32
		want    int32
		wantErr bool
	}{
		{"zero minus zero", 0, 0, 0, false},
		{"small subtraction", 10, 3, 7, false},
		{"max minus neg one overflow", math.MaxInt32, -1, 0, true},
		{"min minus pos one overflow", math.MinInt32, 1, 0, true},
		{"near boundary safe", math.MaxInt32 - 5, -5, math.MaxInt32, false},
		{"zero minus min overflow", 0, math.MinInt32, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Sub(tt.a, tt.b)
			if ok == tt.wantErr {
				t.Errorf("Sub(%d, %d) ok = %v, wantErr %v", tt.a, tt.b, ok, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Sub(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestSub_int16(t *testing.T) {
	tests := []struct {
		name    string
		a, b    int16
		want    int16
		wantErr bool
	}{
		{"zero minus zero", 0, 0, 0, false},
		{"small subtraction", 10, 3, 7, false},
		{"result negative", 3, 10, -7, false},
		{"max minus neg one overflow", math.MaxInt16, -1, 0, true},
		{"min minus pos one overflow", math.MinInt16, 1, 0, true},
		{"near boundary safe", math.MaxInt16 - 5, -5, math.MaxInt16, false},
		{"min minus itself", math.MinInt16, math.MinInt16, 0, false},
		{"zero minus min overflow", 0, math.MinInt16, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Sub(tt.a, tt.b)
			if ok == tt.wantErr {
				t.Errorf("Sub(%d, %d) ok = %v, wantErr %v", tt.a, tt.b, ok, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Sub(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestSub_int8(t *testing.T) {
	tests := []struct {
		name    string
		a, b    int8
		want    int8
		wantErr bool
	}{
		{"zero minus zero", 0, 0, 0, false},
		{"small subtraction", 10, 3, 7, false},
		{"result negative", 3, 10, -7, false},
		{"max minus neg one overflow", math.MaxInt8, -1, 0, true},
		{"min minus pos one overflow", math.MinInt8, 1, 0, true},
		{"near boundary safe", math.MaxInt8 - 5, -5, math.MaxInt8, false},
		{"large negative minus large positive", math.MinInt8 + 5, 10, 0, true},
		{"zero minus min overflow", 0, math.MinInt8, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Sub(tt.a, tt.b)
			if ok == tt.wantErr {
				t.Errorf("Sub(%d, %d) ok = %v, wantErr %v", tt.a, tt.b, ok, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Sub(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestMul(t *testing.T) {
	tests := []struct {
		name    string
		a, b    int64
		want    int64
		wantErr bool
	}{
		// Zero cases
		{"zero times zero", 0, 0, 0, false},
		{"zero times positive", 0, 100, 0, false},
		{"positive times zero", 100, 0, 0, false},
		{"zero times negative", 0, -100, 0, false},
		{"negative times zero", -100, 0, 0, false},
		{"zero times max", 0, math.MaxInt64, 0, false},
		{"zero times min", 0, math.MinInt64, 0, false},

		// One cases
		{"one times one", 1, 1, 1, false},
		{"one times positive", 1, 100, 100, false},
		{"positive times one", 100, 1, 100, false},
		{"one times negative", 1, -100, -100, false},
		{"negative times one", -100, 1, -100, false},
		{"one times max", 1, math.MaxInt64, math.MaxInt64, false},
		{"one times min", 1, math.MinInt64, math.MinInt64, false},

		// Negative one cases
		{"neg one times positive", -1, 100, -100, false},
		{"positive times neg one", 100, -1, -100, false},
		{"neg one times negative", -1, -100, 100, false},
		{"negative times neg one", -100, -1, 100, false},
		{"neg one times max", -1, math.MaxInt64, -math.MaxInt64, false},
		{"neg one times min overflow", -1, math.MinInt64, 0, true},
		{"min times neg one overflow", math.MinInt64, -1, 0, true},

		// Small multiplications
		{"small positives", 7, 8, 56, false},
		{"small negatives", -7, -8, 56, false},
		{"mixed signs", 7, -8, -56, false},
		{"mixed signs reverse", -7, 8, -56, false},

		// Larger safe multiplications
		{"larger safe", 1000, 1000, 1000000, false},
		{"larger safe mixed", 1000, -1000, -1000000, false},

		// Boundary safe cases
		{"sqrt max approx", 3037000499, 3037000499, 9223372030926249001, false},
		{"max div 2", math.MaxInt64 / 2, 2, math.MaxInt64 - 1, false},
		{"near max safe", math.MaxInt64 / 100, 100, math.MaxInt64 - math.MaxInt64%100, false},

		// Overflow cases - positive result overflow
		{"overflow large positives", math.MaxInt64 / 2, 3, 0, true},
		{"overflow max times two", math.MaxInt64, 2, 0, true},
		{"overflow max times max", math.MaxInt64, math.MaxInt64, 0, true},
		{"overflow sqrt max plus one", 3037000500, 3037000500, 0, true},

		// Overflow cases - negative result overflow
		{"overflow large mixed", math.MaxInt64 / 2, -3, 0, true},
		{"overflow max times neg two", math.MaxInt64, -2, 0, true},
		{"overflow min times two", math.MinInt64, 2, 0, true},
		{"overflow min times max", math.MinInt64, math.MaxInt64, 0, true},

		// Overflow to positive from two negatives
		{"overflow two negatives", math.MinInt64 / 2, -3, 0, true},
		{"overflow min times min", math.MinInt64, math.MinInt64, 0, true},

		// Edge cases with MinInt64
		{"min times one", math.MinInt64, 1, math.MinInt64, false},
		{"min div 2 times 2", math.MinInt64 / 2, 2, math.MinInt64, false},

		// Off-by-one boundary tests
		{"overflow boundary positive", math.MaxInt64/2 + 1, 2, 0, true},
		{"overflow boundary negative", math.MinInt64/2 - 1, 2, 0, true},
		{"negative square", -2, -2, 4, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Mul(tt.a, tt.b)
			if ok == tt.wantErr {
				t.Errorf("Mul(%d, %d) ok = %v, wantErr %v", tt.a, tt.b, ok, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Mul(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestMul_int32(t *testing.T) {
	tests := []struct {
		name    string
		a, b    int32
		want    int32
		wantErr bool
	}{
		{"zero times zero", 0, 0, 0, false},
		{"small multiplication", 7, 8, 56, false},
		{"one times max", 1, math.MaxInt32, math.MaxInt32, false},
		{"neg one times min overflow", -1, math.MinInt32, 0, true},
		{"min times neg one overflow", math.MinInt32, -1, 0, true},
		{"overflow positive", math.MaxInt32 / 2, 3, 0, true},
		{"safe near max", 46340, 46340, 2147395600, false},
		{"overflow sqrt boundary", 46341, 46341, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Mul(tt.a, tt.b)
			if ok == tt.wantErr {
				t.Errorf("Mul(%d, %d) ok = %v, wantErr %v", tt.a, tt.b, ok, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Mul(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestMul_int16(t *testing.T) {
	tests := []struct {
		name    string
		a, b    int16
		want    int16
		wantErr bool
	}{
		{"zero times zero", 0, 0, 0, false},
		{"small multiplication", 7, 8, 56, false},
		{"one times max", 1, math.MaxInt16, math.MaxInt16, false},
		{"one times min", 1, math.MinInt16, math.MinInt16, false},
		{"neg one times min overflow", -1, math.MinInt16, 0, true},
		{"min times neg one overflow", math.MinInt16, -1, 0, true},
		{"neg one times max", -1, math.MaxInt16, -math.MaxInt16, false},
		{"safe near max", 181, 181, 32761, false},
		{"overflow sqrt boundary", 182, 182, 0, true},
		{"overflow positive", math.MaxInt16 / 2, 3, 0, true},
		{"mixed signs safe", 100, -100, -10000, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Mul(tt.a, tt.b)
			if ok == tt.wantErr {
				t.Errorf("Mul(%d, %d) ok = %v, wantErr %v", tt.a, tt.b, ok, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Mul(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestMul_int8(t *testing.T) {
	tests := []struct {
		name    string
		a, b    int8
		want    int8
		wantErr bool
	}{
		{"zero times zero", 0, 0, 0, false},
		{"small multiplication", 3, 4, 12, false},
		{"one times max", 1, math.MaxInt8, math.MaxInt8, false},
		{"one times min", 1, math.MinInt8, math.MinInt8, false},
		{"neg one times min overflow", -1, math.MinInt8, 0, true},
		{"min times neg one overflow", math.MinInt8, -1, 0, true},
		{"neg one times max", -1, math.MaxInt8, -math.MaxInt8, false},
		{"safe near max", 11, 11, 121, false},
		{"overflow sqrt boundary", 12, 12, 0, true},
		{"overflow positive", math.MaxInt8 / 2, 3, 0, true},
		{"mixed signs safe", 10, -10, -100, false},
		{"mixed signs overflow", 15, -10, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Mul(tt.a, tt.b)
			if ok == tt.wantErr {
				t.Errorf("Mul(%d, %d) ok = %v, wantErr %v", tt.a, tt.b, ok, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Mul(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestAdd_uint64(t *testing.T) {
	tests := []struct {
		name    string
		a, b    uint64
		want    uint64
		wantErr bool
	}{
		// Basic cases
		{"zero plus zero", 0, 0, 0, false},
		{"zero plus positive", 0, 5, 5, false},
		{"positive plus zero", 5, 0, 5, false},

		// Normal additions
		{"small values", 1, 2, 3, false},
		{"larger values", 1000, 2000, 3000, false},
		{"near max safe", math.MaxUint64 - 10, 5, math.MaxUint64 - 5, false},
		{"at boundary", math.MaxUint64 - 1, 1, math.MaxUint64, false},

		// Overflow cases
		{"overflow max plus one", math.MaxUint64, 1, 0, true},
		{"overflow max plus max", math.MaxUint64, math.MaxUint64, 0, true},
		{"overflow large values", math.MaxUint64 - 5, 10, 0, true},
		{"overflow half max doubled", math.MaxUint64/2 + 1, math.MaxUint64/2 + 1, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Add(tt.a, tt.b)
			if ok == tt.wantErr {
				t.Errorf("Add(%d, %d) ok = %v, wantErr %v", tt.a, tt.b, ok, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Add(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestAdd_uint32(t *testing.T) {
	tests := []struct {
		name    string
		a, b    uint32
		want    uint32
		wantErr bool
	}{
		{"zero plus zero", 0, 0, 0, false},
		{"small values", 1, 2, 3, false},
		{"at boundary", math.MaxUint32 - 1, 1, math.MaxUint32, false},
		{"overflow max plus one", math.MaxUint32, 1, 0, true},
		{"overflow large values", math.MaxUint32 - 5, 10, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Add(tt.a, tt.b)
			if ok == tt.wantErr {
				t.Errorf("Add(%d, %d) ok = %v, wantErr %v", tt.a, tt.b, ok, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Add(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestAdd_uint16(t *testing.T) {
	tests := []struct {
		name    string
		a, b    uint16
		want    uint16
		wantErr bool
	}{
		{"zero plus zero", 0, 0, 0, false},
		{"small values", 1, 2, 3, false},
		{"larger values", 1000, 2000, 3000, false},
		{"at boundary", math.MaxUint16 - 1, 1, math.MaxUint16, false},
		{"overflow max plus one", math.MaxUint16, 1, 0, true},
		{"overflow large values", math.MaxUint16 - 5, 10, 0, true},
		{"overflow half max doubled", math.MaxUint16/2 + 1, math.MaxUint16/2 + 1, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Add(tt.a, tt.b)
			if ok == tt.wantErr {
				t.Errorf("Add(%d, %d) ok = %v, wantErr %v", tt.a, tt.b, ok, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Add(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestAdd_uint8(t *testing.T) {
	tests := []struct {
		name    string
		a, b    uint8
		want    uint8
		wantErr bool
	}{
		{"zero plus zero", 0, 0, 0, false},
		{"small values", 1, 2, 3, false},
		{"larger values", 100, 50, 150, false},
		{"at boundary", math.MaxUint8 - 1, 1, math.MaxUint8, false},
		{"overflow max plus one", math.MaxUint8, 1, 0, true},
		{"overflow large values", math.MaxUint8 - 5, 10, 0, true},
		{"overflow half max doubled", math.MaxUint8/2 + 1, math.MaxUint8/2 + 1, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Add(tt.a, tt.b)
			if ok == tt.wantErr {
				t.Errorf("Add(%d, %d) ok = %v, wantErr %v", tt.a, tt.b, ok, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Add(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestSub_uint64(t *testing.T) {
	tests := []struct {
		name    string
		a, b    uint64
		want    uint64
		wantErr bool
	}{
		// Basic cases
		{"zero minus zero", 0, 0, 0, false},
		{"positive minus zero", 5, 0, 5, false},
		{"same values", 100, 100, 0, false},

		// Normal subtractions
		{"small values", 10, 3, 7, false},
		{"larger values", 3000, 1000, 2000, false},
		{"max minus one", math.MaxUint64, 1, math.MaxUint64 - 1, false},
		{"max minus max", math.MaxUint64, math.MaxUint64, 0, false},
		{"max minus almost max", math.MaxUint64, math.MaxUint64 - 5, 5, false},

		// Underflow cases
		{"underflow zero minus one", 0, 1, 0, true},
		{"underflow small minus large", 5, 10, 0, true},
		{"underflow zero minus max", 0, math.MaxUint64, 0, true},
		{"underflow one minus max", 1, math.MaxUint64, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Sub(tt.a, tt.b)
			if ok == tt.wantErr {
				t.Errorf("Sub(%d, %d) ok = %v, wantErr %v", tt.a, tt.b, ok, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Sub(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestSub_uint32(t *testing.T) {
	tests := []struct {
		name    string
		a, b    uint32
		want    uint32
		wantErr bool
	}{
		{"zero minus zero", 0, 0, 0, false},
		{"small subtraction", 10, 3, 7, false},
		{"max minus one", math.MaxUint32, 1, math.MaxUint32 - 1, false},
		{"underflow zero minus one", 0, 1, 0, true},
		{"underflow small minus large", 5, 10, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Sub(tt.a, tt.b)
			if ok == tt.wantErr {
				t.Errorf("Sub(%d, %d) ok = %v, wantErr %v", tt.a, tt.b, ok, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Sub(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestSub_uint16(t *testing.T) {
	tests := []struct {
		name    string
		a, b    uint16
		want    uint16
		wantErr bool
	}{
		{"zero minus zero", 0, 0, 0, false},
		{"small subtraction", 10, 3, 7, false},
		{"larger subtraction", 1000, 500, 500, false},
		{"max minus one", math.MaxUint16, 1, math.MaxUint16 - 1, false},
		{"max minus max", math.MaxUint16, math.MaxUint16, 0, false},
		{"underflow zero minus one", 0, 1, 0, true},
		{"underflow small minus large", 5, 10, 0, true},
		{"underflow zero minus max", 0, math.MaxUint16, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Sub(tt.a, tt.b)
			if ok == tt.wantErr {
				t.Errorf("Sub(%d, %d) ok = %v, wantErr %v", tt.a, tt.b, ok, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Sub(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestSub_uint8(t *testing.T) {
	tests := []struct {
		name    string
		a, b    uint8
		want    uint8
		wantErr bool
	}{
		{"zero minus zero", 0, 0, 0, false},
		{"small subtraction", 10, 3, 7, false},
		{"larger subtraction", 200, 100, 100, false},
		{"max minus one", math.MaxUint8, 1, math.MaxUint8 - 1, false},
		{"max minus max", math.MaxUint8, math.MaxUint8, 0, false},
		{"underflow zero minus one", 0, 1, 0, true},
		{"underflow small minus large", 5, 10, 0, true},
		{"underflow zero minus max", 0, math.MaxUint8, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Sub(tt.a, tt.b)
			if ok == tt.wantErr {
				t.Errorf("Sub(%d, %d) ok = %v, wantErr %v", tt.a, tt.b, ok, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Sub(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestMul_uint64(t *testing.T) {
	tests := []struct {
		name    string
		a, b    uint64
		want    uint64
		wantErr bool
	}{
		// Zero cases
		{"zero times zero", 0, 0, 0, false},
		{"zero times positive", 0, 100, 0, false},
		{"positive times zero", 100, 0, 0, false},
		{"zero times max", 0, math.MaxUint64, 0, false},

		// One cases
		{"one times one", 1, 1, 1, false},
		{"one times positive", 1, 100, 100, false},
		{"positive times one", 100, 1, 100, false},
		{"one times max", 1, math.MaxUint64, math.MaxUint64, false},
		{"max times one", math.MaxUint64, 1, math.MaxUint64, false},

		// Small multiplications
		{"small values", 7, 8, 56, false},
		{"larger safe", 1000, 1000, 1000000, false},

		// Boundary safe cases
		{"sqrt max approx", 4294967295, 4294967295, 18446744065119617025, false},
		{"max div 2", math.MaxUint64 / 2, 2, math.MaxUint64 - 1, false},
		{"near max safe", math.MaxUint64 / 100, 100, math.MaxUint64 - math.MaxUint64%100, false},

		// Overflow cases
		{"overflow large values", math.MaxUint64 / 2, 3, 0, true},
		{"overflow max times two", math.MaxUint64, 2, 0, true},
		{"overflow max times max", math.MaxUint64, math.MaxUint64, 0, true},
		{"overflow sqrt max plus one", 4294967296, 4294967296, 0, true},
		{"overflow near boundary", math.MaxUint64 - 5, 2, 0, true},

		// High-bit boundary tests
		{"high bit boundary safe", 1 << 63, 1, 1 << 63, false},
		{"high bit boundary overflow", 1 << 63, 2, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Mul(tt.a, tt.b)
			if ok == tt.wantErr {
				t.Errorf("Mul(%d, %d) ok = %v, wantErr %v", tt.a, tt.b, ok, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Mul(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestMul_uint32(t *testing.T) {
	tests := []struct {
		name    string
		a, b    uint32
		want    uint32
		wantErr bool
	}{
		{"zero times zero", 0, 0, 0, false},
		{"small multiplication", 7, 8, 56, false},
		{"one times max", 1, math.MaxUint32, math.MaxUint32, false},
		{"max times one", math.MaxUint32, 1, math.MaxUint32, false},
		{"safe near max", 65535, 65535, 4294836225, false},
		{"overflow sqrt boundary", 65536, 65536, 0, true},
		{"overflow max times two", math.MaxUint32, 2, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Mul(tt.a, tt.b)
			if ok == tt.wantErr {
				t.Errorf("Mul(%d, %d) ok = %v, wantErr %v", tt.a, tt.b, ok, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Mul(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestMul_uint16(t *testing.T) {
	tests := []struct {
		name    string
		a, b    uint16
		want    uint16
		wantErr bool
	}{
		{"zero times zero", 0, 0, 0, false},
		{"small multiplication", 7, 8, 56, false},
		{"one times max", 1, math.MaxUint16, math.MaxUint16, false},
		{"max times one", math.MaxUint16, 1, math.MaxUint16, false},
		{"safe near max", 255, 255, 65025, false},
		{"overflow sqrt boundary", 256, 256, 0, true},
		{"overflow max times two", math.MaxUint16, 2, 0, true},
		{"overflow large values", math.MaxUint16 / 2, 3, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Mul(tt.a, tt.b)
			if ok == tt.wantErr {
				t.Errorf("Mul(%d, %d) ok = %v, wantErr %v", tt.a, tt.b, ok, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Mul(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestMul_uint8(t *testing.T) {
	tests := []struct {
		name    string
		a, b    uint8
		want    uint8
		wantErr bool
	}{
		{"zero times zero", 0, 0, 0, false},
		{"small multiplication", 3, 4, 12, false},
		{"one times max", 1, math.MaxUint8, math.MaxUint8, false},
		{"max times one", math.MaxUint8, 1, math.MaxUint8, false},
		{"safe near max", 15, 15, 225, false},
		{"overflow sqrt boundary", 16, 16, 0, true},
		{"overflow max times two", math.MaxUint8, 2, 0, true},
		{"overflow large values", math.MaxUint8 / 2, 3, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Mul(tt.a, tt.b)
			if ok == tt.wantErr {
				t.Errorf("Mul(%d, %d) ok = %v, wantErr %v", tt.a, tt.b, ok, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Mul(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestCommutativity(t *testing.T) {
	signedValues := []int64{
		0, 1, -1, 2, -2,
		100, -100,
		math.MaxInt64, math.MinInt64,
		math.MaxInt64 - 1, math.MinInt64 + 1,
	}

	unsignedValues := []uint64{
		0, 1, 2,
		100,
		math.MaxUint64, math.MaxUint64 - 1,
		math.MaxUint64 / 2,
	}

	t.Run("Add_signed", func(t *testing.T) {
		for _, a := range signedValues {
			for _, b := range signedValues {
				r1, ok1 := Add(a, b)
				r2, ok2 := Add(b, a)
				if ok1 != ok2 {
					t.Errorf("Add commutativity ok mismatch: Add(%d, %d) ok=%v, Add(%d, %d) ok=%v",
						a, b, ok1, b, a, ok2)
				}
				if ok1 && r1 != r2 {
					t.Errorf("Add commutativity result mismatch: Add(%d, %d)=%d, Add(%d, %d)=%d",
						a, b, r1, b, a, r2)
				}
			}
		}
	})

	t.Run("Add_unsigned", func(t *testing.T) {
		for _, a := range unsignedValues {
			for _, b := range unsignedValues {
				r1, ok1 := Add(a, b)
				r2, ok2 := Add(b, a)
				if ok1 != ok2 {
					t.Errorf("Add commutativity ok mismatch: Add(%d, %d) ok=%v, Add(%d, %d) ok=%v",
						a, b, ok1, b, a, ok2)
				}
				if ok1 && r1 != r2 {
					t.Errorf("Add commutativity result mismatch: Add(%d, %d)=%d, Add(%d, %d)=%d",
						a, b, r1, b, a, r2)
				}
			}
		}
	})

	t.Run("Mul_signed", func(t *testing.T) {
		for _, a := range signedValues {
			for _, b := range signedValues {
				r1, ok1 := Mul(a, b)
				r2, ok2 := Mul(b, a)
				if ok1 != ok2 {
					t.Errorf("Mul commutativity ok mismatch: Mul(%d, %d) ok=%v, Mul(%d, %d) ok=%v",
						a, b, ok1, b, a, ok2)
				}
				if ok1 && r1 != r2 {
					t.Errorf("Mul commutativity result mismatch: Mul(%d, %d)=%d, Mul(%d, %d)=%d",
						a, b, r1, b, a, r2)
				}
			}
		}
	})

	t.Run("Mul_unsigned", func(t *testing.T) {
		for _, a := range unsignedValues {
			for _, b := range unsignedValues {
				r1, ok1 := Mul(a, b)
				r2, ok2 := Mul(b, a)
				if ok1 != ok2 {
					t.Errorf("Mul commutativity ok mismatch: Mul(%d, %d) ok=%v, Mul(%d, %d) ok=%v",
						a, b, ok1, b, a, ok2)
				}
				if ok1 && r1 != r2 {
					t.Errorf("Mul commutativity result mismatch: Mul(%d, %d)=%d, Mul(%d, %d)=%d",
						a, b, r1, b, a, r2)
				}
			}
		}
	})
}

func TestSub_NonCommutative(t *testing.T) {
	tests := []struct {
		a, b int64
	}{
		{10, 5},
		{math.MinInt64, 0},
		{1, 0},
		{100, 50},
		{-10, 5},
	}

	for _, tt := range tests {
		r1, ok1 := Sub(tt.a, tt.b)
		r2, ok2 := Sub(tt.b, tt.a)

		// If one succeeds and the other doesn't, they are different (Pass)
		if ok1 != ok2 {
			continue
		}

		// If both succeed, the results must be different (unless a == b)
		if ok1 && r1 == r2 && tt.a != tt.b {
			t.Errorf("Sub should not be commutative for %d and %d: Sub(%d,%d)=%d, Sub(%d,%d)=%d",
				tt.a, tt.b, tt.a, tt.b, r1, tt.b, tt.a, r2)
		}
	}
}
