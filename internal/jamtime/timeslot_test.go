package jamtime

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCurrentTimeslot(t *testing.T) {
	t.Run("current timeslot is valid", func(t *testing.T) {
		currentTimeslot := CurrentTimeslot()
		err2 := ValidateTimeslot(currentTimeslot)
		assert.NoError(t, err2)
	})
}

func TestValidateTimeSlot(t *testing.T) {
	t.Run("is valid timeslot", func(t *testing.T) {
		validTimeslot := Timeslot(1000000)
		err := ValidateTimeslot(validTimeslot)
		assert.NoError(t, err)
	})

	t.Run("max timeslot is valid", func(t *testing.T) {
		maxTimeslot := MaxTimeslot

		err := ValidateTimeslot(maxTimeslot)
		assert.NoError(t, err)
	})
}

func TestTimeSlot_IsInFuture(t *testing.T) {
	t.Run("timeslot should be in the future", func(t *testing.T) {
		validTime := time.Date(2500, time.July, 27, 0, 0, 0, 0, time.UTC)

		jamTime, err := FromTime(validTime)
		assert.Nil(t, err)
		ts := jamTime.ToTimeslot()

		isInFuture := ts.IsInFuture()

		assert.True(t, isInFuture)
	})

	t.Run("timeslot should be not in the future", func(t *testing.T) {
		validTime := time.Date(2025, time.January, 27, 0, 0, 0, 0, time.UTC)

		jamTime, err := FromTime(validTime)
		assert.Nil(t, err)
		ts := jamTime.ToTimeslot()

		isInFuture := ts.IsInFuture()

		assert.False(t, isInFuture)
	})
}

func TestTimeSlot_TimeslotStart(t *testing.T) {
	t.Run("should be able to get to the start timeslot", func(t *testing.T) {
		first := Timeslot(1)
		want, err := FromTime(time.Date(2025, time.January, 01, 12, 00, 06, 0, time.UTC))
		assert.Nil(t, err)

		got := first.TimeslotStart()
		assert.Equal(t, want.Seconds, got.Seconds)
	})
}

func TestTimeSlot_TimeslotEnd(t *testing.T) {
	t.Run("should be able to go to the end timeslot", func(t *testing.T) {
		first := Timeslot(1)
		want, err := FromTime(time.Date(2025, time.January, 01, 12, 00, 11, 0, time.UTC))
		assert.Nil(t, err)

		got, err := first.TimeslotEnd()
		assert.NoError(t, err)
		assert.Equal(t, want.Seconds, got.Seconds)
	})

	t.Run("if max time slot then we've already reached the end", func(t *testing.T) {
		maxTimeslot := MaxTimeslot

		zeroJamTime, err := maxTimeslot.TimeslotEnd()
		assert.Error(t, err)
		assert.True(t, zeroJamTime.IsZero())
		assert.ErrorIs(t, err, ErrMaxTimeslotReached)
	})
}

func TestTimeSlot_NextTimeslot(t *testing.T) {
	t.Run("should get the next timeslot", func(t *testing.T) {
		first := Timeslot(1)
		got, err := first.NextTimeslot()
		assert.NoError(t, err)

		expected := Timeslot(2)

		assert.Equal(t, expected, got)
	})

	t.Run("call to NextTimeslot at MaxTimeslot should error", func(t *testing.T) {
		ts := MaxTimeslot
		_, err := ts.NextTimeslot()
		assert.ErrorIs(t, err, ErrMaxTimeslotReached)
	})
}

func TestTimeSlot_PreviousTimeslot(t *testing.T) {
	t.Run("should get the previous timeslot", func(t *testing.T) {
		first := Timeslot(2)
		got, err := first.PreviousTimeslot()
		assert.NoError(t, err)

		expected := Timeslot(1)

		assert.Equal(t, expected, got)
	})

	t.Run("call to PreviousTimeslot at MinTimeslot should return error", func(t *testing.T) {
		ts := MinTimeslot
		_, err := ts.PreviousTimeslot()
		assert.ErrorIs(t, err, ErrMinTimeslotReached)
	})
}

func TestTimeSlot_TimeslotInEpoch(t *testing.T) {
	t.Run("first timeslot of first epoch", func(t *testing.T) {
		ts := Timeslot(0)
		result := ts.TimeslotInEpoch()

		assert.Equal(t, uint32(0), result)
		assert.True(t, ts.IsFirstTimeslotInEpoch())
		assert.False(t, ts.IsLastTimeslotInEpoch())
	})

	t.Run("last timeslot of first epoch", func(t *testing.T) {
		ts := Timeslot(599)
		result := ts.TimeslotInEpoch()

		assert.Equal(t, uint32(599), result)
		assert.False(t, ts.IsFirstTimeslotInEpoch())
		assert.True(t, ts.IsLastTimeslotInEpoch())
	})

	t.Run("middle timeslot of first epoch", func(t *testing.T) {
		ts := Timeslot(300)
		result := ts.TimeslotInEpoch()

		assert.Equal(t, uint32(300), result)
		assert.False(t, ts.IsFirstTimeslotInEpoch())
		assert.False(t, ts.IsLastTimeslotInEpoch())
	})

	t.Run("first timeslot of second epoch", func(t *testing.T) {
		ts := Timeslot(600)
		result := ts.TimeslotInEpoch()

		assert.Equal(t, uint32(0), result)
		assert.True(t, ts.IsFirstTimeslotInEpoch())
		assert.False(t, ts.IsLastTimeslotInEpoch())
	})

	t.Run("random timeslot in a later epoch", func(t *testing.T) {
		ts := Timeslot(123456)
		result := ts.TimeslotInEpoch()

		assert.Equal(t, uint32(456), result)
		assert.False(t, ts.IsFirstTimeslotInEpoch())
		assert.False(t, ts.IsLastTimeslotInEpoch())
	})

	t.Run("Max timeslot", func(t *testing.T) {
		ts := Timeslot(4294967295) // 2^32 - 1
		result := ts.TimeslotInEpoch()
		assert.Equal(t, uint32(495), result)
		assert.False(t, ts.IsFirstTimeslotInEpoch())
		assert.False(t, ts.IsLastTimeslotInEpoch())
	})
}

func TestTimeSlot_ToEpoch(t *testing.T) {
	t.Run("first timeslot of first epoch", func(t *testing.T) {
		ts := Timeslot(0)
		epoch := ts.ToEpoch()
		assert.Equal(t, Epoch(0), epoch)
	})

	t.Run("last timeslot of first epoch", func(t *testing.T) {
		ts := Timeslot(599)
		epoch := ts.ToEpoch()
		assert.Equal(t, Epoch(0), epoch)
	})

	t.Run("first timeslot of second epoch", func(t *testing.T) {
		ts := Timeslot(600)
		epoch := ts.ToEpoch()
		assert.Equal(t, Epoch(1), epoch)
	})

	t.Run("middle timeslot of arbitrary epoch", func(t *testing.T) {
		ts := Timeslot(123456)
		epoch := ts.ToEpoch()
		assert.Equal(t, Epoch(205), epoch)
	})

	t.Run("last timeslot of arbitrary epoch", func(t *testing.T) {
		ts := Timeslot(1199)
		epoch := ts.ToEpoch()
		assert.Equal(t, Epoch(1), epoch)
	})

	t.Run("first timeslot of last possible epoch", func(t *testing.T) {
		ts := Timeslot(4294966800) // 7158278 * 600
		epoch := ts.ToEpoch()
		assert.Equal(t, Epoch(7158278), epoch)
	})

	t.Run("last timeslot of last possible epoch", func(t *testing.T) {
		ts := Timeslot(4294967295) // uint32 max
		epoch := ts.ToEpoch()
		assert.Equal(t, Epoch(7158278), epoch)
	})

	t.Run("epoch boundary check", func(t *testing.T) {
		ts1 := Timeslot(599)
		ts2 := Timeslot(600)
		assert.NotEqual(t, ts1.ToEpoch(), ts2.ToEpoch())
	})

	t.Run("large timeslot value", func(t *testing.T) {
		ts := Timeslot(1000000)
		epoch := ts.ToEpoch()
		assert.Equal(t, Epoch(1666), epoch)
	})

	t.Run("consistency check with TimeslotInEpoch", func(t *testing.T) {
		ts := Timeslot(12345)
		epoch := ts.ToEpoch()
		inEpoch := ts.TimeslotInEpoch()

		want := Timeslot(uint32(epoch)*600 + inEpoch)

		assert.Equal(t, ts, want)
	})
}

func TestTimeSlot_IsTicketSubmissionPeriod(t *testing.T) {
	tests := []struct {
		name     string
		timeslot Timeslot
		want     bool
	}{
		{
			name:     "First slot in epoch",
			timeslot: 0,
			want:     true,
		},
		{
			name:     "Last submission slot",
			timeslot: TicketSubmissionTimeSlots - 1,
			want:     true,
		},
		{
			name:     "First non-submission slot",
			timeslot: TicketSubmissionTimeSlots,
			want:     false,
		},
		{
			name:     "Last slot in epoch",
			timeslot: TimeslotsPerEpoch - 1,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.timeslot.IsTicketSubmissionPeriod()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsWinningTicketMarkerPeriod(t *testing.T) {
	tests := []struct {
		name     string
		next     Timeslot
		previous Timeslot
		want     bool
	}{
		{
			name:     "First winning marker slot",
			next:     TicketSubmissionTimeSlots,
			previous: TicketSubmissionTimeSlots - 1,
			want:     true,
		},
		{
			name:     "Winning marker slot, early submission slot, late end submission slot",
			next:     TicketSubmissionTimeSlots + 1,
			previous: TicketSubmissionTimeSlots - 6,
			want:     true,
		},
		{
			name:     "Both slots in submission period",
			next:     TicketSubmissionTimeSlots - 2,
			previous: TicketSubmissionTimeSlots - 3,
			want:     false,
		},
		{
			name:     "Both slots after submission period",
			next:     TicketSubmissionTimeSlots + 1,
			previous: TicketSubmissionTimeSlots,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.next.IsWinningTicketMarkerPeriod(tt.previous)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsLastCoreRotation(t *testing.T) {
	lastRotationStart := TimeslotsPerEpoch - ValidatorRotationPeriod

	assert.False(t, Timeslot(0).IsLastCoreRotation())
	assert.False(t, (lastRotationStart - 1).IsLastCoreRotation())
	assert.True(t, lastRotationStart.IsLastCoreRotation())
	assert.True(t, Timeslot(TimeslotsPerEpoch-1).IsLastCoreRotation())
}
