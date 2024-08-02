package jamtime

import (
	"errors"
	"testing"
	"time"
)

func TestEpoch_FromEpoch(t *testing.T) {
	t.Run("first epoch", func(t *testing.T) {
		jt := FromEpoch(0)
		if jt.Seconds != 0 {
			t.Errorf("FromEpoch(0): got %d, want 0", jt.Seconds)
		}
	})

	t.Run("arbitrary epoch", func(t *testing.T) {
		jt := FromEpoch(100)
		expected := uint64(360000) // 100 * 3600
		if jt.Seconds != expected {
			t.Errorf("FromEpoch(100): got %d, want %d", jt.Seconds, expected)
		}
	})

	t.Run("last possible epoch", func(t *testing.T) {
		jt := FromEpoch(7158278)
		expected := uint64(25769800800) // 7158278 * 3600
		if jt.Seconds != expected {
			t.Errorf("FromEpoch(7158278): got %d, want %d", jt.Seconds, expected)
		}
	})
}

func TestEpoch_ToEpoch(t *testing.T) {
	t.Run("start of first epoch", func(t *testing.T) {
		jt := JamTime{Seconds: 0}
		epoch := jt.ToEpoch()
		if epoch != 0 {
			t.Errorf("ToEpoch() for Seconds 0: got %d, want 0", epoch)
		}
	})

	t.Run("middle of arbitrary epoch", func(t *testing.T) {
		jt := JamTime{Seconds: 3601} // 1 second into the second epoch
		epoch := jt.ToEpoch()
		if epoch != 1 {
			t.Errorf("ToEpoch() for Seconds 3601: got %d, want 1", epoch)
		}
	})

	t.Run("end of last possible epoch", func(t *testing.T) {
		jt := JamTime{Seconds: 25769803199} // Last second of the last epoch
		epoch := jt.ToEpoch()
		if epoch != 7158278 {
			t.Errorf("ToEpoch() for Seconds 25769803199: got %d, want 7158278", epoch)
		}
	})
}

func TestEpoch_CurrentEpoch(t *testing.T) {
	currentEpoch := CurrentEpoch()
	now := time.Now().UTC()
	expectedEpoch := Epoch((now.Unix() - JamEpoch.Unix()) / 3600)
	if currentEpoch != expectedEpoch {
		t.Errorf("CurrentEpoch() should equal same as expected: got %d, want %d", currentEpoch, expectedEpoch)
	}
}

func TestEpoch_EpochStart(t *testing.T) {
	t.Run("first epoch", func(t *testing.T) {
		start := Epoch(0).EpochStart()
		expected := uint64(0)
		if start.Seconds != expected {
			t.Errorf("EpochStart() should return JamTime at expected: %d, but got: %d", expected, start.Seconds)
		}
	})

	t.Run("arbitrary epoch", func(t *testing.T) {
		start := Epoch(100).EpochStart()
		expected := uint64(360000) // 100 * 3600
		if start.Seconds != expected {
			t.Errorf("EpochStart() should return JamTime at expected: %d, but got: %d", expected, start.Seconds)
		}
	})
}

func TestEpoch_EpochEnd(t *testing.T) {
	t.Run("first epoch", func(t *testing.T) {
		end := Epoch(0).EpochEnd()
		expected := uint64(3600)
		if end.Seconds != expected {
			t.Errorf("EpochEnd() should return JamTime at expected: %d, but got: %d", expected, end.Seconds)
		}
	})

	t.Run("arbitrary epoch", func(t *testing.T) {
		end := Epoch(100).EpochEnd()
		expected := uint64(363600) // (100 * 3600) + 3599
		if end.Seconds != expected {
			t.Errorf("EpochEnd() should return JamTime at expected: %d, but got: %d", expected, end.Seconds)
		}
	})

	t.Run("max epoch returns jam time for last timeslot", func(t *testing.T) {
		jamTime := MaxEpoch.EpochEnd()
		expected := FromTimeslot(MaxTimeslot)
		if jamTime.Seconds != expected.Seconds {
			t.Errorf("MaxEpoch.EpochEnd() should return JamTime at expected: %d, but got: %d", expected, jamTime.Seconds)
		}
	})
}

func TestEpoch_NextEpoch(t *testing.T) {
	t.Run("from first epoch", func(t *testing.T) {
		next, err := Epoch(0).NextEpoch()
		if err != nil {
			t.Fatalf("did not expect error for Epoch(0).NextEpoch(): %v", err)
		}

		if next != Epoch(1) {
			t.Errorf("Epoch(0).NextEpoch() should return Epoch(1) but got: %d", next)
		}
	})

	t.Run("call to NextEpoch at MaxEpoch causes error", func(t *testing.T) {
		e := MaxEpoch
		_, err := e.NextEpoch()
		if !errors.Is(err, ErrMaxEpochReached) {
			t.Errorf("NextEpoch() should return ErrMaxEpochReached when MaxEpoch is reached: %v", err)
		}
	})
}

func TestEpoch_PreviousEpoch(t *testing.T) {
	t.Run("from second epoch", func(t *testing.T) {
		prev, err := Epoch(1).PreviousEpoch()
		if err != nil {
			t.Fatalf("did not expect error for Epoch(1).PreviousEpoch(): %v", err)
		}
		if prev != Epoch(0) {
			t.Errorf("Epoch(1).PreviousEpoch() should have returned Epoch(0) but got: %d", prev)
		}
	})

	t.Run("call to PreviousEpoch at MinEpoch causes error", func(t *testing.T) {
		e := MinEpoch
		_, err := e.PreviousEpoch()
		if !errors.Is(err, ErrMinEpochReached) {
			t.Errorf("PreviousEpoch() should return ErrMaxEpochReached when MinEpoch is reached: %v", err)
		}
	})
}

func TestEpoch_ValidateEpoch(t *testing.T) {
	t.Run("valid epoch", func(t *testing.T) {
		err := ValidateEpoch(1000)
		if err != nil {
			t.Errorf("expected ValidateEpoch(1000) to return nil error: %v", err)
		}
	})

	t.Run("min valid epoch", func(t *testing.T) {
		err := ValidateEpoch(MinEpoch)
		if err != nil {
			t.Errorf("expected ValidateEpoch(MinEpoch) to return nil error: %v", err)
		}
	})

	t.Run("max valid epoch", func(t *testing.T) {
		err := ValidateEpoch(MaxEpoch)
		if err != nil {
			t.Errorf("expected ValidateEpoch(MaxEpoch) to return nil error: %v", err)
		}
	})

	t.Run("Epoch too large", func(t *testing.T) {
		err := ValidateEpoch(MaxEpoch + 1)
		if !errors.Is(err, ErrEpochExceedsMaxJamTime) {
			t.Errorf("expected ValidateEpoch(MaxEpoch + 1) to return ErrEpochExceedsMaxJamTime")
		}
	})
}
