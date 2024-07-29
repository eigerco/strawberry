package jamtime

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
)

func TestJamTime_FromTime(t *testing.T) {
	t.Run("successfully convert from time.Time to JamTime", func(t *testing.T) {
		standardTime := time.Date(2025, time.March, 15, 12, 0, 0, 0, time.UTC)
		jamTime := FromTime(standardTime)
		convertedTime := jamTime.ToTime()

		qt.Assert(t, qt.IsTrue(standardTime.Equal(convertedTime)))
	})
}

func TestJamTime_FromSeconds(t *testing.T) {
	t.Run("successfully convert from seconds to JamTime", func(t *testing.T) {
		secondsInYear := uint64(31_536_000)
		jamTime := FromSeconds(secondsInYear)
		expectedTime := JamEpoch.Add(time.Duration(secondsInYear) * time.Second)

		qt.Assert(t, qt.IsTrue(jamTime.ToTime().Equal(expectedTime)))
	})
}

func TestJamTimeComparison(t *testing.T) {
	t.Run("non equal", func(t *testing.T) {
		t1 := FromSeconds(1000)
		t2 := FromSeconds(2000)

		qt.Assert(t, qt.IsTrue(t1.Before(t2)))
		qt.Assert(t, qt.IsTrue(t2.After(t1)))
		qt.Assert(t, qt.IsFalse(t1.Equal(t2)))
	})

	t.Run("equal", func(t *testing.T) {
		t1 := FromSeconds(1000)
		t2 := FromSeconds(1000)

		qt.Assert(t, qt.IsTrue(t1.Equal(t2)))
		qt.Assert(t, qt.IsTrue(t2.Equal(t1)))
	})
}

func TestJamTimeArithmetic(t *testing.T) {
	t.Run("adding jamtime", func(t *testing.T) {
		t1 := FromSeconds(1000)
		duration := 500 * time.Second

		t2 := t1.Add(duration)
		qt.Assert(t, qt.Not(qt.Equals(t2, t1)))
		qt.Assert(t, qt.Equals(time.Duration(t2.Seconds)*time.Second, time.Duration(1500)*time.Second))
	})

	t.Run("subbing jamtime", func(t *testing.T) {
		t1 := FromSeconds(1000)
		t2 := FromSeconds(500)

		duration := t1.Sub(t2)
		qt.Assert(t, qt.Equals(duration, time.Duration(500)*time.Second))
	})
}

func TestJamTimeJSON(t *testing.T) {
	t.Run("successfully marshal to json", func(t *testing.T) {
		jamTime := FromSeconds(1000)
		jsonData, err := json.Marshal(jamTime)
		if err != nil {
			t.Fatalf("JSON marshaling failed: %v", err)
		}

		qt.Assert(t, qt.DeepEquals(jsonData, []uint8(`"2024-01-01T12:16:40Z"`)))
	})

	t.Run("successfully unmarshal jamtime", func(t *testing.T) {
		jsonData := []byte(`"2024-01-01T12:00:00Z"`)

		var unmarshaledTime JamTime
		err := json.Unmarshal(jsonData, &unmarshaledTime)
		if err != nil {
			t.Fatalf("JSON unmarshaling failed: %v", err)
		}

		qt.Assert(t, qt.IsTrue(unmarshaledTime.ToTime().Equal(JamEpoch)))
	})

	t.Run("successfully unmarshal jamtime in future", func(t *testing.T) {
		jsonData := []byte(`"2024-01-01T12:00:01Z"`)

		var unmarshaledTime JamTime
		err := json.Unmarshal(jsonData, &unmarshaledTime)
		if err != nil {
			t.Fatalf("JSON unmarshaling failed: %v", err)
		}

		want := JamEpoch.Add(1 * time.Second)

		qt.Assert(t, qt.IsTrue(unmarshaledTime.ToTime().Equal(want)))
	})
}

func TestJamTimeFromToTimeslotConversion(t *testing.T) {
	t.Run("convert jamtime to timeslot", func(t *testing.T) {
		jamTime := FromSeconds(3600) // 10 minutes after JAM Epoch
		timeslot := jamTime.ToTimeslot()

		qt.Assert(t, qt.Equals(uint32(timeslot), 600))
	})

	t.Run("convert timeslot to jamtime", func(t *testing.T) {
		slot := Timeslot(100)

		jamTime := FromTimeslot(slot)

		qt.Assert(t, qt.Equals(jamTime.Seconds, 600))
	})
}

func TestJamTime_IsInFutureTimeSlot(t *testing.T) {
	currentTime := Now()
	pastTime := currentTime.Add(-5 * time.Minute)
	futureTime := currentTime.Add(10 * time.Minute)

	qt.Assert(t, qt.IsFalse(currentTime.IsInFutureTimeSlot()))
	qt.Assert(t, qt.IsFalse(pastTime.IsInFutureTimeSlot()))
	qt.Assert(t, qt.IsTrue(futureTime.IsInFutureTimeSlot()))
}

func TestJamTime_ToEpoch(t *testing.T) {
	t.Run("jamtime to epoch", func(t *testing.T) {
		jamTime := FromSeconds(3600) // 1 hour after JAM Epoch
		epoch := jamTime.ToEpoch()

		qt.Assert(t, qt.Equals(epoch, 1))
	})
}

func TestJamTech_FromEpoch(t *testing.T) {
	t.Run("epoch to jamtime", func(t *testing.T) {
		e := Epoch(1)

		convertedJamTime := FromEpoch(e)

		qt.Assert(t, qt.Equals(convertedJamTime.Seconds, 3600))
	})
}

func TestEpochAndTimeslotConversion(t *testing.T) {
	t.Run("successfully converts jamtime to epoch and timeslot", func(t *testing.T) {
		jamTime := FromSeconds(3600) // 1 hour after JAM Epoch

		epoch, timeslot := jamTime.ToEpochAndTimeslot()
		qt.Assert(t, qt.Equals(epoch, Epoch(1)))
		qt.Assert(t, qt.Equals(timeslot, Timeslot(0)))
	})

	t.Run("successfull converts epoch and timeslot to jamtime", func(t *testing.T) {
		timeslot := Timeslot(1)
		epoch := Epoch(1)

		jamTime, err := EpochAndTimeslotToJamTime(epoch, timeslot)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(jamTime.Seconds, 3606))
	})

	t.Run("returns an error when timeslot is outside of accepted range", func(t *testing.T) {
		timeslot := Timeslot(601)
		epoch := Epoch(1)

		jamTime, err := EpochAndTimeslotToJamTime(epoch, timeslot)
		qt.Assert(t, qt.IsNotNil(err))
		qt.Assert(t, qt.ErrorMatches(err, "timeslot number exceeds epoch length"))
		qt.Assert(t, qt.IsTrue(jamTime.IsZero()))
	})
}

func TestValidateJamTime(t *testing.T) {
	t.Run("today is valid", func(t *testing.T) {
		now := time.Now()

		err := ValidateJamTime(now)
		qt.Assert(t, qt.IsNil(err))
	})

	t.Run("the future should be valid", func(t *testing.T) {
		validTime := time.Date(2500, time.July, 27, 0, 0, 0, 0, time.UTC)

		err := ValidateJamTime(validTime)
		qt.Assert(t, qt.IsNil(err))
	})

	t.Run("far into the future should be invalid", func(t *testing.T) {
		inValidTime := time.Date(2840, time.August, 31, 23, 59, 59, 999999999, time.UTC)

		err := ValidateJamTime(inValidTime)
		qt.Assert(t, qt.IsNotNil(err))
		qt.Assert(t, qt.ErrorMatches(err, "time is after maximum representable JAM time"))
	})

	t.Run("date before January 1st 2024 is invalid", func(t *testing.T) {
		invalidTime := time.Date(2023, time.December, 31, 0, 0, 0, 0, time.UTC)
		err := ValidateJamTime(invalidTime)
		qt.Assert(t, qt.IsNotNil(err))
		qt.Assert(t, qt.ErrorMatches(err, "time is before JAM Epoch"))
	})

	validEpoch := Epoch(1000)
	if err := ValidateEpoch(validEpoch); err != nil {
		t.Errorf("ValidateEpoch failed for valid epoch: %v", err)
	}

}

func TestJamTime_IsInSameEpoch(t *testing.T) {
	t.Run("same epoch - beginning", func(t *testing.T) {
		time1 := JamTime{Seconds: 0}
		time2 := JamTime{Seconds: 3599}
		qt.Assert(t, qt.IsTrue(time1.IsInSameEpoch(time2)))
	})

	t.Run("same epoch - middle", func(t *testing.T) {
		time1 := JamTime{Seconds: 3600*100 + 1800}
		time2 := JamTime{Seconds: 3600*100 + 3599}
		qt.Assert(t, qt.IsTrue(time1.IsInSameEpoch(time2)))
	})

	t.Run("different epochs - consecutive", func(t *testing.T) {
		time1 := JamTime{Seconds: 3599}
		time2 := JamTime{Seconds: 3600}
		qt.Assert(t, qt.IsFalse(time1.IsInSameEpoch(time2)))
	})

	t.Run("different epochs - far apart", func(t *testing.T) {
		time1 := JamTime{Seconds: 3600 * 100}
		time2 := JamTime{Seconds: 3600 * 200}
		qt.Assert(t, qt.IsFalse(time1.IsInSameEpoch(time2)))
	})

	t.Run("same time", func(t *testing.T) {
		time1 := JamTime{Seconds: 3600 * 50}
		qt.Assert(t, qt.IsTrue(time1.IsInSameEpoch(time1)))
	})

	t.Run("epoch boundary - end of epoch", func(t *testing.T) {
		time1 := JamTime{Seconds: 3600 - 1}
		time2 := JamTime{Seconds: 3600}
		qt.Assert(t, qt.IsFalse(time1.IsInSameEpoch(time2)))
	})

	t.Run("epoch boundary - start of epoch", func(t *testing.T) {
		time1 := JamTime{Seconds: 3600}
		time2 := JamTime{Seconds: 3600 + 1}
		qt.Assert(t, qt.IsTrue(time1.IsInSameEpoch(time2)))
	})

	t.Run("max time value", func(t *testing.T) {
		maxTime := JamTime{Seconds: ^uint64(0)}
		almostMaxTime := JamTime{Seconds: ^uint64(0) - 3599}
		qt.Assert(t, qt.IsFalse(maxTime.IsInSameEpoch(almostMaxTime)))
	})

	t.Run("zero and almost one epoch", func(t *testing.T) {
		time1 := JamTime{Seconds: 0}
		time2 := JamTime{Seconds: 3599}
		qt.Assert(t, qt.IsTrue(time1.IsInSameEpoch(time2)))
	})

	t.Run("fromtime conversion", func(t *testing.T) {
		now := time.Now()
		jamTime1 := FromTime(now)
		jamTime2 := FromTime(now.Add(59 * time.Minute))
		qt.Assert(t, qt.IsFalse(jamTime1.IsInSameEpoch(jamTime2)))
	})

	t.Run("fromtime conversion - different epochs", func(t *testing.T) {
		now := time.Now()
		jamTime1 := FromTime(now)
		jamTime2 := FromTime(now.Add(61 * time.Minute))
		qt.Assert(t, qt.IsFalse(jamTime1.IsInSameEpoch(jamTime2)))
	})
}
