package jamtime

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
)

func TestJamTimeConversion(t *testing.T) {
	t.Run("successfully convert to to and from JamTime", func(t *testing.T) {
		standardTime := time.Date(2025, time.March, 15, 12, 0, 0, 0, time.UTC)
		jamTime := FromTime(standardTime)
		convertedTime := jamTime.ToTime()

		qt.Assert(t, qt.IsTrue(standardTime.Equal(convertedTime)))

		secondsInYear := uint64(31_536_000)
		jamTime = FromSeconds(secondsInYear)
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

func TestJamTimeIsInFutureTimeSlot(t *testing.T) {
	currentTime := Now()
	pastTime := currentTime.Add(-5 * time.Minute)
	futureTime := currentTime.Add(10 * time.Minute)

	qt.Assert(t, qt.IsFalse(currentTime.IsInFutureTimeSlot()))
	qt.Assert(t, qt.IsFalse(pastTime.IsInFutureTimeSlot()))
	qt.Assert(t, qt.IsTrue(futureTime.IsInFutureTimeSlot()))
}

func TestEpochConversion(t *testing.T) {
	t.Run("jamtime to epoch", func(t *testing.T) {
		jamTime := FromSeconds(3600) // 1 hour after JAM Epoch
		epoch := jamTime.ToEpoch()

		qt.Assert(t, qt.Equals(epoch, 1))
	})

	t.Run("epoch to jamtime", func(t *testing.T) {
		e := Epoch(1)

		convertedJamTime := FromEpoch(e)

		qt.Assert(t, qt.Equals(convertedJamTime.Seconds, 3600))
	})
}
