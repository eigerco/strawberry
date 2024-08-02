package jamtime

import (
	"errors"
	"testing"
	"time"
)

func TestValidateTimeSlot(t *testing.T) {
	t.Run("is valid timeslot", func(t *testing.T) {
		validTimeslot := Timeslot(1000000)
		err := ValidateTimeslot(validTimeslot)
		if err != nil {
			t.Fatalf("expected no error from valid timeslot")
		}
	})

	t.Run("max timeslot is valid", func(t *testing.T) {
		maxTimeslot := MaxTimeslot

		err := ValidateTimeslot(maxTimeslot)
		if err != nil {
			t.Fatalf("expected no error from valid max timeslot")
		}
	})
}

func TestTimeSlot_IsInFuture(t *testing.T) {
	t.Run("timeslot should be in the future", func(t *testing.T) {
		validTime := time.Date(2500, time.July, 27, 0, 0, 0, 0, time.UTC)

		jamTime := FromTime(validTime)
		ts := jamTime.ToTimeslot()

		isInFuture := ts.IsInFuture()

		if !isInFuture {
			t.Errorf("expected TimeSlot in future")
		}
	})

	t.Run("timeslot should be not in the future", func(t *testing.T) {
		validTime := time.Date(2024, time.January, 27, 0, 0, 0, 0, time.UTC)

		jamTime := FromTime(validTime)
		ts := jamTime.ToTimeslot()

		isInFuture := ts.IsInFuture()

		if isInFuture {
			t.Errorf("expected TimeSlot in not in the future")
		}
	})

}

func TestTimeSlot_TimeslotStart(t *testing.T) {
	t.Run("should be able to get to the start timeslot", func(t *testing.T) {
		first := Timeslot(1)
		want := FromTime(time.Date(2024, time.January, 01, 12, 00, 06, 0, time.UTC))

		got := first.TimeslotStart()
		if got.Seconds != want.Seconds {
			t.Errorf("expected TimeslotStart to return JamTime at %d but got %d", want.Seconds, got.Seconds)
		}
	})

}

func TestTimeSlot_TimeslotEnd(t *testing.T) {
	t.Run("should be able to go to the end timeslot", func(t *testing.T) {
		first := Timeslot(1)
		want := FromTime(time.Date(2024, time.January, 01, 12, 00, 12, 0, time.UTC))

		got, err := first.TimeslotEnd()
		if err != nil {
			t.Fatalf("expected no error when calling TimeslotEnd but got: %v", err)
		}
		if got.Seconds != want.Seconds {
			t.Errorf("expected TimeslotEnd to return JamTime at %d but got %d", want.Seconds, got.Seconds)
		}
	})

	t.Run("if max time slot then we've already reached the end", func(t *testing.T) {
		maxTimeslot := MaxTimeslot

		zeroJamTime, err := maxTimeslot.TimeslotEnd()
		if err == nil {
			t.Fatal("expected error when calling TimeslotEnd on MaxTimeslot")
		}
		if !zeroJamTime.IsZero() {
			t.Fatal("expected zero jamtime with error")
		}
		if !errors.Is(err, ErrMaxTimeslotReached) {
			t.Errorf("expected ErrMaxTimeslotReached when calling TimeslotEnd on MaxTimeslot but got: %v", err)
		}
	})
}

func TestTimeSlot_NextTimeslot(t *testing.T) {
	t.Run("should get the next timeslot", func(t *testing.T) {
		first := Timeslot(1)
		got, err := first.NextTimeslot()
		if err != nil {
			t.Fatalf("expected no error when calling NextTimeslot but got: %v", err)
		}

		expected := Timeslot(2)

		if got != expected {
			t.Errorf("expected NextTimeslot to return %d but got %d", expected, got)
		}
	})

	t.Run("call to NextTimeslot at MaxTimeslot should error", func(t *testing.T) {
		ts := MaxTimeslot
		_, err := ts.NextTimeslot()
		if !errors.Is(err, ErrMaxTimeslotReached) {
			t.Fatalf("expected ErrMaxTimeslotReached when calling NextTimeslot but got: %v", err)
		}
	})
}

func TestTimeSlot_PreviousTimeslot(t *testing.T) {
	t.Run("should get the previous timeslot", func(t *testing.T) {
		first := Timeslot(2)
		got, err := first.PreviousTimeslot()
		if err != nil {
			t.Fatalf("expected no error when calling PreviousTimeslot but got: %v", err)
		}

		expected := Timeslot(1)

		if got != expected {
			t.Errorf("expected PreviousTimeslot to return %d but got %d", expected, got)
		}
	})

	t.Run("call to PreviousTimeslot at MinTimeslot should return error", func(t *testing.T) {
		ts := MinTimeslot
		_, err := ts.PreviousTimeslot()
		if !errors.Is(err, ErrMinTimeslotReached) {
			t.Fatalf("expected ErrMinTimeslotReached when calling PreviousTimeslot but got: %v", err)
		}
	})
}

func TestTimeSlot_TimeslotInEpoch(t *testing.T) {
	t.Run("first timeslot of first epoch", func(t *testing.T) {
		ts := Timeslot(0)
		result := ts.TimeslotInEpoch()

		if result != 0 {
			t.Errorf("expected result to be 0 but got: %d", result)
		}
		if !ts.IsFirstTimeslotInEpoch() {
			t.Errorf("expected IsFirstTimeslotInEpoch to be true")
		}
		if ts.IsLastTimeslotInEpoch() {
			t.Errorf("expected IsLastTimeslotInEpoch to be false")
		}
	})

	t.Run("last timeslot of first epoch", func(t *testing.T) {
		ts := Timeslot(599)
		result := ts.TimeslotInEpoch()

		if result != 599 {
			t.Errorf("expected result to be 599 but got: %d", result)
		}
		if ts.IsFirstTimeslotInEpoch() {
			t.Errorf("expected IsFirstTimeslotInEpoch to be false")
		}
		if !ts.IsLastTimeslotInEpoch() {
			t.Errorf("expected IsLastTimeslotInEpoch to be true")
		}
	})

	t.Run("middle timeslot of first epoch", func(t *testing.T) {
		ts := Timeslot(300)
		result := ts.TimeslotInEpoch()

		if result != 300 {
			t.Errorf("expected result to be 300 but got: %d", result)
		}
		if ts.IsFirstTimeslotInEpoch() {
			t.Errorf("expected IsFirstTimeslotInEpoch to be false")
		}
		if ts.IsLastTimeslotInEpoch() {
			t.Errorf("expected IsLastTimeslotInEpoch to be false")
		}
	})

	t.Run("first timeslot of second epoch", func(t *testing.T) {
		ts := Timeslot(600)
		result := ts.TimeslotInEpoch()

		if result != 0 {
			t.Errorf("expected result to be 0 but got: %d", result)
		}
		if !ts.IsFirstTimeslotInEpoch() {
			t.Errorf("expected IsFirstTimeslotInEpoch to be true")
		}
		if ts.IsLastTimeslotInEpoch() {
			t.Errorf("expected IsLastTimeslotInEpoch to be false")
		}
	})

	t.Run("random timeslot in a later epoch", func(t *testing.T) {
		ts := Timeslot(123456)
		result := ts.TimeslotInEpoch()

		if result != 456 {
			t.Errorf("expected result to be 456 but got: %d", result)
		}
		if ts.IsFirstTimeslotInEpoch() {
			t.Errorf("expected IsFirstTimeslotInEpoch to be false")
		}
		if ts.IsLastTimeslotInEpoch() {
			t.Errorf("expected IsLastTimeslotInEpoch to be false")
		}
	})

	t.Run("Max timeslot", func(t *testing.T) {
		ts := Timeslot(4294967295) // 2^32 - 1
		result := ts.TimeslotInEpoch()
		if result != 495 {
			t.Errorf("expected result to be 495 but got: %d", result)
		}
		if ts.IsFirstTimeslotInEpoch() {
			t.Errorf("expected IsFirstTimeslotInEpoch to be false")
		}
		if ts.IsLastTimeslotInEpoch() {
			t.Errorf("expected IsLastTimeslotInEpoch to be false")
		}
	})
}

func TestTimeSlot_ToEpoch(t *testing.T) {
	t.Run("first timeslot of first epoch", func(t *testing.T) {
		ts := Timeslot(0)
		epoch := ts.ToEpoch()
		if epoch != 0 {
			t.Errorf("expected epoch to be equal to 0 but got: %d", epoch)
		}
	})

	t.Run("last timeslot of first epoch", func(t *testing.T) {
		ts := Timeslot(599)
		epoch := ts.ToEpoch()
		if epoch != 0 {
			t.Errorf("expected epoch to be equal to 0 but got: %d", epoch)
		}
	})

	t.Run("first timeslot of second epoch", func(t *testing.T) {
		ts := Timeslot(600)
		epoch := ts.ToEpoch()
		if epoch != 1 {
			t.Errorf("expected epoch to be equal to 1 but got: %d", epoch)
		}
	})

	t.Run("middle timeslot of arbitrary epoch", func(t *testing.T) {
		ts := Timeslot(123456)
		epoch := ts.ToEpoch()
		if epoch != 205 {
			t.Errorf("expected epoch to be equal to 205 but got: %d", epoch)
		}
	})

	t.Run("last timeslot of arbitrary epoch", func(t *testing.T) {
		ts := Timeslot(1199)
		epoch := ts.ToEpoch()
		if epoch != 1 {
			t.Errorf("expected epoch to be equal to 1 but got: %d", epoch)
		}
	})

	t.Run("first timeslot of last possible epoch", func(t *testing.T) {
		ts := Timeslot(4294966800) // 7158278 * 600
		epoch := ts.ToEpoch()
		if epoch != 7158278 {
			t.Errorf("expected epoch to be equal to 7158278 but got: %d", epoch)
		}
	})

	t.Run("last timeslot of last possible epoch", func(t *testing.T) {
		ts := Timeslot(4294967295) // uint32 max
		epoch := ts.ToEpoch()
		if epoch != 7158278 {
			t.Errorf("expected epoch to be equal to 7158278 but got: %d", epoch)
		}
	})

	t.Run("epoch boundary check", func(t *testing.T) {
		ts1 := Timeslot(599)
		ts2 := Timeslot(600)
		if ts1.ToEpoch() == ts2.ToEpoch() {
			t.Errorf("expected epochs ts1 and ts2 to be not be the same got: %d - %d", ts1.ToEpoch(), ts2.ToEpoch())
		}
	})

	t.Run("large timeslot value", func(t *testing.T) {
		ts := Timeslot(1000000)
		epoch := ts.ToEpoch()
		if epoch != 1666 {
			t.Errorf("expected epoch to be equal to 1666 but got: %d", epoch)
		}
	})

	t.Run("consistency check with TimeslotInEpoch", func(t *testing.T) {
		ts := Timeslot(12345)
		epoch := ts.ToEpoch()
		inEpoch := ts.TimeslotInEpoch()

		want := Timeslot(uint32(epoch)*600 + inEpoch)

		if ts != want {
			t.Errorf("expected timeslots to be expected %d but got %d", ts, want)
		}
	})
}
