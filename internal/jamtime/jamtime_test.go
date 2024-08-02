package jamtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestJamTime_FromTime(t *testing.T) {
	t.Run("successfully convert from time.Time to JamTime", func(t *testing.T) {
		standardTime := time.Date(2025, time.March, 15, 12, 0, 0, 0, time.UTC)
		jamTime := FromTime(standardTime)
		convertedTime := jamTime.ToTime()

		if !standardTime.Equal(convertedTime) {
			t.Errorf("expected standardTime to be equal to convertedTime")
		}
	})
}

func TestJamTime_FromSeconds(t *testing.T) {
	t.Run("successfully convert from seconds to JamTime", func(t *testing.T) {
		secondsInYear := uint64(31_536_000)
		jamTime := FromSeconds(secondsInYear)
		expectedTime := JamEpoch.Add(time.Duration(secondsInYear) * time.Second)

		if !jamTime.ToTime().Equal(expectedTime) {
			t.Errorf("expected jamTime.ToTime() to be equal to expectedTime")
		}
	})
}

func TestJamTimeComparison(t *testing.T) {
	t.Run("non equal", func(t *testing.T) {
		t1 := FromSeconds(1000)
		t2 := FromSeconds(2000)

		if !t1.Before(t2) {
			t.Errorf("expected t1 to not be before t2: %d < %d", t1.Seconds, t2.Seconds)
		}

		if !t2.After(t1) {
			t.Errorf("expected t2 to not be after t1: %d > %d", t2.Seconds, t1.Seconds)
		}

		if t1.Equal(t2) {
			t.Errorf("expected t1 and t2 to not be equal: %d == %d", t1.Seconds, t2.Seconds)
		}
	})

	t.Run("equal", func(t *testing.T) {
		t1 := FromSeconds(1000)
		t2 := FromSeconds(1000)

		if !t1.Equal(t2) {
			t.Errorf("expected t1 and t2 to be equal: %d != %d", t1.Seconds, t2.Seconds)
		}

		if !t2.Equal(t1) {
			t.Errorf("expected t2 and t1 to be equal: %d != %d", t2.Seconds, t1.Seconds)
		}
	})
}

func TestJamTimeArithmetic(t *testing.T) {
	t.Run("adding jamtime", func(t *testing.T) {
		t1 := FromSeconds(1000)
		duration := 500 * time.Second

		t2 := t1.Add(duration)
		if t2.Equal(t1) {
			t.Errorf("did not expected t2 to be equal to t1: %d == %d", t2.Seconds, t1.Seconds)
		}

		if t2.Seconds == t1.Seconds {
			t.Errorf("did not expected t2 to be equal to t1: %d == %d", t2.Seconds, t1.Seconds)
		}
	})

	t.Run("subbing jamtime", func(t *testing.T) {
		t1 := FromSeconds(1000)
		t2 := FromSeconds(500)

		duration := t1.Sub(t2)
		if duration != time.Duration(500)*time.Second {
			t.Errorf("expected duration to be 500s got: %f", duration.Seconds())
		}
	})
}

func TestJamTime_MarshalJSON(t *testing.T) {
	t.Run("successfully marshal to json", func(t *testing.T) {
		jamTime := FromSeconds(1000)
		jsonData, err := json.Marshal(jamTime)
		if err != nil {
			t.Fatalf("did not expect error from json.Marshal: %v", err)
		}

		expected := []byte(`"2024-01-01T12:16:40Z"`)

		if !bytes.Equal(jsonData, expected) {
			t.Errorf("expected jsonData to be %s but got %s", expected, jsonData)
		}
	})
}

func TestJamTime_UnmarshalJSON(t *testing.T) {
	t.Run("successfully unmarshal jamtime", func(t *testing.T) {
		jsonData := []byte(`"2024-01-01T12:00:00Z"`)

		var unmarshaledTime JamTime
		err := json.Unmarshal(jsonData, &unmarshaledTime)
		if err != nil {
			t.Fatalf("did not expect error from json.Unmarshal: %v", err)
		}

		got := unmarshaledTime.ToTime()

		if !got.Equal(JamEpoch) {
			t.Errorf("expected unmarshaledTime.ToTime() to be equal to JamEpoch but got: %s", got.Format(time.RFC3339))
		}
	})

	t.Run("successfully unmarshal jamtime in future", func(t *testing.T) {
		jsonData := []byte(`"2024-01-01T12:00:01Z"`)
		want := JamEpoch.Add(1 * time.Second)

		var unmarshaledTime JamTime
		err := json.Unmarshal(jsonData, &unmarshaledTime)
		if err != nil {
			t.Fatalf("did not expect error from json.Unmarshal: %v", err)
		}

		got := unmarshaledTime.ToTime()
		if !got.Equal(want) {
			t.Errorf("expected unmarshaledTime.ToTime() to be equal to %s but got: %s", want.Format(time.RFC3339), got.Format(time.RFC3339))
		}
	})

	t.Run("errors when unmarshalling unknown data structure", func(t *testing.T) {
		jsonData := []byte(`asdasdasd`)
		var unmarshaledTime JamTime

		err := unmarshaledTime.UnmarshalJSON(jsonData)
		if err == nil {
			t.Fatalf("expected error from json.Unmarshal")
		}

		if err.Error() != `parsing time "asdasdasd" as "\"2006-01-02T15:04:05Z07:00\"": cannot parse "asdasdasd" as "\""` {
			t.Errorf("expected parsing time error but got: %s", err.Error())
		}
	})
}

func TestJamTimeFromToTimeslotConversion(t *testing.T) {
	t.Run("convert jamtime to timeslot", func(t *testing.T) {
		jamTime := FromSeconds(3600) // 10 minutes after JAM Epoch
		timeslot := jamTime.ToTimeslot()

		expected := Timeslot(600)
		if timeslot != expected {
			t.Errorf("expected timeslot to be equal got %d expected %d", timeslot, expected)
		}
	})

	t.Run("convert timeslot to jamtime", func(t *testing.T) {
		slot := Timeslot(100)

		jamTime := FromTimeslot(slot)
		expected := uint64(600)
		if jamTime.Seconds != expected {
			t.Errorf("expected jamTime.Seconds to be equal got %d expected %d", jamTime.Seconds, expected)
		}
	})
}

func TestJamTime_IsInFutureTimeSlot(t *testing.T) {
	currentTime := Now()
	pastTime := currentTime.Add(-5 * time.Minute)
	futureTime := currentTime.Add(10 * time.Minute)

	if currentTime.IsInFutureTimeSlot() {
		t.Errorf("expected currentTime to not be in future timeslot")
	}
	if pastTime.IsInFutureTimeSlot() {
		t.Errorf("expected pastTime to not be in future timeslot")
	}
	if !futureTime.IsInFutureTimeSlot() {
		t.Errorf("expected futureTime to be in future timeslot")
	}
}

func TestJamTime_ToEpoch(t *testing.T) {
	t.Run("jamtime to epoch", func(t *testing.T) {
		jamTime := FromSeconds(3600) // 1 hour after JAM Epoch
		epoch := jamTime.ToEpoch()
		expected := Epoch(1)
		if epoch != expected {
			t.Errorf("expected epoch to be equal to %d but got %d", expected, epoch)
		}
	})
}

func TestJamTech_FromEpoch(t *testing.T) {
	t.Run("epoch to jamtime", func(t *testing.T) {
		e := Epoch(1)

		convertedJamTime := FromEpoch(e)

		if convertedJamTime.Seconds != uint64(3600) {
			t.Errorf("expected convertedJamTime.Seconds to equal to 3600 but got: %d", convertedJamTime.Seconds)
		}
	})
}

func TestEpochAndTimeslotConversion(t *testing.T) {
	t.Run("successfully converts jamtime to epoch and timeslot", func(t *testing.T) {
		jamTime := FromSeconds(3600) // 1 hour after JAM Epoch

		epoch, timeslot := jamTime.ToEpochAndTimeslot()
		expectedEpoch := Epoch(1)
		expectedTimeslot := Timeslot(0)

		if epoch != expectedEpoch {
			t.Errorf("expected epoch to be equal to expected %d but got: %d", expectedEpoch, epoch)
		}

		if timeslot != expectedTimeslot {
			t.Errorf("expected timeslot to be equal to expected %d but got: %d", expectedTimeslot, timeslot)
		}
	})

	t.Run("successfull converts epoch and timeslot to jamtime", func(t *testing.T) {
		timeslot := Timeslot(1)
		epoch := Epoch(1)

		jamTime, err := EpochAndTimeslotToJamTime(epoch, timeslot)
		if err != nil {
			t.Fatalf("unexpected when calling EpochAndTimeslotToJamTime err: %v", err)
		}

		expected := uint64(3606)

		if jamTime.Seconds != expected {
			t.Errorf("expected jamTime to be equal to %d but got: %d", expected, jamTime.Seconds)
		}
	})

	t.Run("returns an error when timeslot is outside of accepted range", func(t *testing.T) {
		timeslot := Timeslot(601)
		epoch := Epoch(1)

		jamTime, err := EpochAndTimeslotToJamTime(epoch, timeslot)
		if err == nil {
			t.Fatalf("expected EpochAndTimeslotToJamTime with incorrect input but did not error")
		}
		if !errors.Is(err, ErrTimeslotExceedsEpochLength) {
			t.Errorf("exepected err to be ErrTimeslotExceedsEpochLength but got: %v", err)
		}
		if !jamTime.IsZero() {
			t.Errorf("expected jamTime to be zero'd")
		}
	})
}

func TestValidateJamTime(t *testing.T) {
	t.Run("today is valid", func(t *testing.T) {
		now := time.Now()

		err := ValidateJamTime(now)
		if err != nil {
			t.Fatalf("unexpected err when validating valid jam time")
		}
	})

	t.Run("the future should be valid", func(t *testing.T) {
		validTime := time.Date(2500, time.July, 27, 0, 0, 0, 0, time.UTC)

		err := ValidateJamTime(validTime)
		if err != nil {
			t.Fatalf("unexecpted err when validating future date within JamTime date range")
		}
	})

	t.Run("far into the future should be invalid", func(t *testing.T) {
		inValidTime := time.Date(2840, time.August, 31, 23, 59, 59, 999999999, time.UTC)

		err := ValidateJamTime(inValidTime)
		if err == nil {
			t.Fatalf("expected error for date far into future")
		}

		if !errors.Is(err, ErrAfterMaxJamTime) {
			t.Errorf("expected ErrAfterMaxJamTime for invalid future date got: %v", err)
		}
	})

	t.Run("date before January 1st 2024 is invalid", func(t *testing.T) {
		invalidTime := time.Date(2023, time.December, 31, 0, 0, 0, 0, time.UTC)
		err := ValidateJamTime(invalidTime)
		if err == nil {
			t.Fatalf("expected error for date before jam epoch")
		}
		if !errors.Is(err, ErrBeforeJamEpoch) {
			t.Errorf("expected ErrBeforeJamEpoch but got: %v", err)
		}
	})
}

func TestJamTime_IsInSameEpoch(t *testing.T) {
	t.Run("same epoch - beginning", func(t *testing.T) {
		time1 := JamTime{Seconds: 0}
		time2 := JamTime{Seconds: 3599}

		if !time1.IsInSameEpoch(time2) {
			t.Errorf("expected time1 and time2 to be in same Epoch")
		}
	})

	t.Run("same epoch - middle", func(t *testing.T) {
		time1 := JamTime{Seconds: 3600*100 + 1800}
		time2 := JamTime{Seconds: 3600*100 + 3599}

		if !time1.IsInSameEpoch(time2) {
			t.Errorf("expected time1 and time2 to be in same Epoch")
		}
	})

	t.Run("different epochs - consecutive", func(t *testing.T) {
		time1 := JamTime{Seconds: 3599}
		time2 := JamTime{Seconds: 3600}

		if time1.IsInSameEpoch(time2) {
			t.Errorf("expected time1 and time2 to not be in same Epoch")
		}
	})

	t.Run("different epochs - far apart", func(t *testing.T) {
		time1 := JamTime{Seconds: 3600 * 100}
		time2 := JamTime{Seconds: 3600 * 200}

		if time1.IsInSameEpoch(time2) {
			t.Errorf("expected time1 and time2 to not be in same Epoch")
		}
	})

	t.Run("same time", func(t *testing.T) {
		time1 := JamTime{Seconds: 3600 * 50}

		if !time1.IsInSameEpoch(time1) {
			t.Errorf("expected time1 and time1 to be in same Epoch")
		}
	})

	t.Run("epoch boundary - end of epoch", func(t *testing.T) {
		time1 := JamTime{Seconds: 3600 - 1}
		time2 := JamTime{Seconds: 3600}

		if time1.IsInSameEpoch(time2) {
			t.Errorf("expected time1 and time2 to not be in same Epoch")
		}
	})

	t.Run("epoch boundary - start of epoch", func(t *testing.T) {
		time1 := JamTime{Seconds: 3600}
		time2 := JamTime{Seconds: 3600 + 1}

		if !time1.IsInSameEpoch(time2) {
			t.Errorf("expected time1 and time2 to not be in same Epoch")
		}
	})

	t.Run("max time value", func(t *testing.T) {
		maxTime := JamTime{Seconds: ^uint64(0)}
		almostMaxTime := JamTime{Seconds: ^uint64(0) - 3599}

		if maxTime.IsInSameEpoch(almostMaxTime) {
			t.Errorf("expected maxTime and almostMaxTime to be in same Epoch")
		}
	})

	t.Run("zero and almost one epoch", func(t *testing.T) {
		time1 := JamTime{Seconds: 0}
		time2 := JamTime{Seconds: 3599}

		if !time1.IsInSameEpoch(time2) {
			t.Errorf("expected time1 and time2 to be in same Epoch")
		}
	})
}
