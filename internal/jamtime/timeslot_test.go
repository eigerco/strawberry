package jamtime

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
)

func TestValidateTimeSlot(t *testing.T) {
	t.Run("is valid timeslot", func(t *testing.T) {
		validTimeslot := Timeslot(1000000)
		err := ValidateTimeslot(validTimeslot)
		qt.Assert(t, qt.IsNil(err))
	})
}

func TestTimeSlot_IsInFuture(t *testing.T) {
	t.Run("timeslot should be in the future", func(t *testing.T) {
		validTime := time.Date(2500, time.July, 27, 0, 0, 0, 0, time.UTC)

		jamTime := FromTime(validTime)
		ts := jamTime.ToTimeslot()

		isInFuture := ts.IsInFuture()

		qt.Assert(t, qt.IsTrue(isInFuture))
	})

	t.Run("timeslot should be not in the future", func(t *testing.T) {
		validTime := time.Date(2024, time.January, 27, 0, 0, 0, 0, time.UTC)

		jamTime := FromTime(validTime)
		ts := jamTime.ToTimeslot()

		isInFuture := ts.IsInFuture()

		qt.Assert(t, qt.IsFalse(isInFuture))
	})

}

func TestTimeSlot_TimeslotStart(t *testing.T) {
	t.Run("should be able to get to the start timeslot", func(t *testing.T) {
		first := Timeslot(1)

		got := first.TimeslotStart()

		want := FromTime(time.Date(2024, time.January, 01, 12, 00, 06, 0, time.UTC))

		qt.Assert(t, qt.DeepEquals(got, want))
	})

}

func TestTimeSlot_TimeslotEnd(t *testing.T) {
	t.Run("should be able to go to the end timeslot", func(t *testing.T) {
		first := Timeslot(1)

		got := first.TimeslotEnd()

		fmt.Println(got.ToTime().Format(time.RFC3339))

		want := FromTime(time.Date(2024, time.January, 01, 12, 00, 12, 0, time.UTC))

		qt.Assert(t, qt.DeepEquals(got, want))
	})
}

func TestTimeSlot_NextTimeslot(t *testing.T) {
	t.Run("should get the next timeslot", func(t *testing.T) {
		first := Timeslot(1)
		next := first.NextTimeslot()

		qt.Assert(t, qt.Equals(next, Timeslot(2)))
	})

	t.Run("should return same last timeslot", func(t *testing.T) {
		last := Timeslot(math.MaxUint32)
		next := last.NextTimeslot()

		qt.Assert(t, qt.Equals(next, Timeslot(math.MaxUint32)))
	})
}

func TestTimeSlot_PreviousTimeslot(t *testing.T) {
	t.Run("should get the previous timeslot", func(t *testing.T) {
		first := Timeslot(2)
		next := first.PreviousTimeslot()

		qt.Assert(t, qt.Equals(next, Timeslot(1)))
	})

	t.Run("should get the same timeslot", func(t *testing.T) {
		first := Timeslot(0)
		next := first.PreviousTimeslot()

		fmt.Println(next)

		qt.Assert(t, qt.Equals(next, Timeslot(0)))
	})

}

func TestTimeSlot_TimeslotInEpoch(t *testing.T) {
	t.Run("first timeslot of first epoch", func(t *testing.T) {
		ts := Timeslot(0)
		result := ts.TimeslotInEpoch()

		qt.Assert(t, qt.Equals(result, 0))
		qt.Assert(t, qt.IsTrue(ts.IsFirstTimeslotInEpoch()))
		qt.Assert(t, qt.IsFalse(ts.IsLastTimeslotInEpoch()))
	})

	t.Run("last timeslot of first epoch", func(t *testing.T) {
		ts := Timeslot(599)
		result := ts.TimeslotInEpoch()

		qt.Assert(t, qt.Equals(result, 599))
		qt.Assert(t, qt.IsFalse(ts.IsFirstTimeslotInEpoch()))
		qt.Assert(t, qt.IsTrue(ts.IsLastTimeslotInEpoch()))
	})

	t.Run("middle timeslot of first epoch", func(t *testing.T) {
		ts := Timeslot(300)
		result := ts.TimeslotInEpoch()

		qt.Assert(t, qt.Equals(result, 300))
		qt.Assert(t, qt.IsFalse(ts.IsFirstTimeslotInEpoch()))
		qt.Assert(t, qt.IsFalse(ts.IsLastTimeslotInEpoch()))
	})

	t.Run("first timeslot of second epoch", func(t *testing.T) {
		ts := Timeslot(600)
		result := ts.TimeslotInEpoch()

		qt.Assert(t, qt.Equals(result, 0))
		qt.Assert(t, qt.IsTrue(ts.IsFirstTimeslotInEpoch()))
		qt.Assert(t, qt.IsFalse(ts.IsLastTimeslotInEpoch()))
	})

	t.Run("random timeslot in a later epoch", func(t *testing.T) {
		ts := Timeslot(123456)
		result := ts.TimeslotInEpoch()

		qt.Assert(t, qt.Equals(result, 456))
		qt.Assert(t, qt.IsFalse(ts.IsFirstTimeslotInEpoch()))
		qt.Assert(t, qt.IsFalse(ts.IsLastTimeslotInEpoch()))
	})

	t.Run("Max timeslot", func(t *testing.T) {
		ts := Timeslot(4294967295) // 2^32 - 1
		result := ts.TimeslotInEpoch()

		qt.Assert(t, qt.Equals(result, 495))
		qt.Assert(t, qt.IsFalse(ts.IsFirstTimeslotInEpoch()))
		qt.Assert(t, qt.IsFalse(ts.IsLastTimeslotInEpoch()))
	})
}

func TestTimeSlot_ToEpoch(t *testing.T) {
	t.Run("first timeslot of first epoch", func(t *testing.T) {
		ts := Timeslot(0)
		epoch := ts.ToEpoch()
		qt.Assert(t, qt.Equals(epoch, 0))
	})

	t.Run("last timeslot of first epoch", func(t *testing.T) {
		ts := Timeslot(599)
		epoch := ts.ToEpoch()
		qt.Assert(t, qt.Equals(epoch, 0))
	})

	t.Run("first timeslot of second epoch", func(t *testing.T) {
		ts := Timeslot(600)
		epoch := ts.ToEpoch()
		qt.Assert(t, qt.Equals(epoch, 1))
	})

	t.Run("middle timeslot of arbitrary epoch", func(t *testing.T) {
		ts := Timeslot(123456)
		epoch := ts.ToEpoch()
		qt.Assert(t, qt.Equals(epoch, 205))
	})

	t.Run("last timeslot of arbitrary epoch", func(t *testing.T) {
		ts := Timeslot(1199)
		epoch := ts.ToEpoch()
		qt.Assert(t, qt.Equals(epoch, 1))
	})

	t.Run("first timeslot of last possible epoch", func(t *testing.T) {
		ts := Timeslot(4294966800) // 7158278 * 600
		epoch := ts.ToEpoch()
		qt.Assert(t, qt.Equals(epoch, 7158278))
	})

	t.Run("last timeslot of last possible epoch", func(t *testing.T) {
		ts := Timeslot(4294967295) // uint32 max
		epoch := ts.ToEpoch()
		qt.Assert(t, qt.Equals(epoch, 7158278))
	})

	t.Run("epoch boundary check", func(t *testing.T) {
		ts1 := Timeslot(599)
		ts2 := Timeslot(600)
		qt.Assert(t, qt.Not(qt.Equals(ts1.ToEpoch(), ts2.ToEpoch())))
	})

	t.Run("large timeslot value", func(t *testing.T) {
		ts := Timeslot(1000000)
		epoch := ts.ToEpoch()
		qt.Assert(t, qt.Equals(epoch, 1666))
	})

	t.Run("consistency check with TimeslotInEpoch", func(t *testing.T) {
		ts := Timeslot(12345)
		epoch := ts.ToEpoch()
		inEpoch := ts.TimeslotInEpoch()

		want := Timeslot(uint32(epoch)*600 + inEpoch)

		qt.Assert(t, qt.Equals(ts, want))
	})
}
