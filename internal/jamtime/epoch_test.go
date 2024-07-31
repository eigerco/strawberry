package jamtime

import (
	"testing"
	"time"

	"github.com/go-quicktest/qt"
)

func TestEpoch_FromEpoch(t *testing.T) {
	t.Run("first epoch", func(t *testing.T) {
		jt := FromEpoch(0)
		qt.Assert(t, qt.Equals(jt.Seconds, 0))
	})

	t.Run("arbitrary epoch", func(t *testing.T) {
		jt := FromEpoch(100)
		qt.Assert(t, qt.Equals(jt.Seconds, 360000)) // 100 * 3600
	})

	t.Run("last possible epoch", func(t *testing.T) {
		jt := FromEpoch(7158278)
		qt.Assert(t, qt.Equals(jt.Seconds, 25769800800)) // 7158278 * 3600
	})
}

func TestEpoch_ToEpoch(t *testing.T) {
	t.Run("start of first epoch", func(t *testing.T) {
		jt := JamTime{Seconds: 0}
		epoch := jt.ToEpoch()
		qt.Assert(t, qt.Equals(epoch, 0))
	})

	t.Run("middle of arbitrary epoch", func(t *testing.T) {
		jt := JamTime{Seconds: 3601} // 1 second into the second epoch
		epoch := jt.ToEpoch()
		qt.Assert(t, qt.Equals(epoch, 1))
	})

	t.Run("end of last possible epoch", func(t *testing.T) {
		jt := JamTime{Seconds: 25769803199} // Last second of the last epoch
		epoch := jt.ToEpoch()
		qt.Assert(t, qt.Equals(epoch, 7158278))
	})
}

func TestEpoch_CurrentEpoch(t *testing.T) {
	currentEpoch := CurrentEpoch()
	now := time.Now().UTC()
	expectedEpoch := Epoch((now.Unix() - JamEpoch.Unix()) / 3600)
	qt.Assert(t, qt.Equals(currentEpoch, expectedEpoch))
}

func TestEpoch_EpochStart(t *testing.T) {
	t.Run("first epoch", func(t *testing.T) {
		start := Epoch(0).EpochStart()
		qt.Assert(t, qt.Equals(start.Seconds, 0))
	})

	t.Run("arbitrary epoch", func(t *testing.T) {
		start := Epoch(100).EpochStart()
		qt.Assert(t, qt.Equals(start.Seconds, 360000)) // 100 * 3600
	})
}

func TestEpoch_EpochEnd(t *testing.T) {
	t.Run("first epoch", func(t *testing.T) {
		end := Epoch(0).EpochEnd()
		qt.Assert(t, qt.Equals(end.Seconds, 3600))
	})

	t.Run("arbitrary epoch", func(t *testing.T) {
		end := Epoch(100).EpochEnd()
		qt.Assert(t, qt.Equals(end.Seconds, 363600)) // (100 * 3600) + 3599
	})

	t.Run("max epoch returns jam time for last timeslot", func(t *testing.T) {
		jamTime := MaxEpoch.EpochEnd()
		want := FromTimeslot(MaxTimeslot)

		qt.Assert(t, qt.DeepEquals(jamTime, want))
	})
}

func TestEpoch_NextEpoch(t *testing.T) {
	t.Run("from first epoch", func(t *testing.T) {
		next, err := Epoch(0).NextEpoch()
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(next, 1))
	})

	t.Run("call to NextEpoch at MaxEpoch causes error", func(t *testing.T) {
		e := MaxEpoch
		_, err := e.NextEpoch()
		qt.Assert(t, qt.ErrorIs(err, ErrMaxEpochReached))
	})
}

func TestEpoch_PreviousEpoch(t *testing.T) {
	t.Run("from second epoch", func(t *testing.T) {
		prev, err := Epoch(1).PreviousEpoch()
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(prev, 0))
	})

	t.Run("call to PreviousEpoch at MinEpoch causes error", func(t *testing.T) {
		e := MinEpoch
		_, err := e.PreviousEpoch()
		qt.Assert(t, qt.ErrorIs(err, ErrMinEpochReached))
	})
}

func TestEpoch_ValidateEpoch(t *testing.T) {
	t.Run("valid epoch", func(t *testing.T) {
		err := ValidateEpoch(1000)
		qt.Assert(t, qt.IsNil(err))
	})

	t.Run("max valid epoch", func(t *testing.T) {
		maxEpoch := Epoch((1<<32 - 1) / TimeslotsPerEpoch)
		err := ValidateEpoch(maxEpoch)
		qt.Assert(t, qt.IsNil(err))
	})

	t.Run("Epoch too large", func(t *testing.T) {
		maxEpoch := Epoch((1<<32 - 1) / TimeslotsPerEpoch)
		err := ValidateEpoch(maxEpoch + 1)
		qt.Assert(t, qt.IsNotNil(err))
		qt.Assert(t, qt.ErrorMatches(err, "epoch is after maximum representable JAM time"))
	})
}
