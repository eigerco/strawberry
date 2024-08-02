package jamtime

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJamTime_FromTime(t *testing.T) {
	t.Run("successfully convert from time.Time to JamTime", func(t *testing.T) {
		standardTime := time.Date(2025, time.March, 15, 12, 0, 0, 0, time.UTC)
		jamTime := FromTime(standardTime)
		convertedTime := jamTime.ToTime()

		assert.True(t, standardTime.Equal(convertedTime))
	})
}

func TestJamTime_FromSeconds(t *testing.T) {
	t.Run("successfully convert from seconds to JamTime", func(t *testing.T) {
		secondsInYear := uint64(31_536_000)
		jamTime := FromSeconds(secondsInYear)
		expectedTime := JamEpoch.Add(time.Duration(secondsInYear) * time.Second)

		assert.True(t, jamTime.ToTime().Equal(expectedTime))
	})
}

func TestJamTimeComparison(t *testing.T) {
	t.Run("non equal", func(t *testing.T) {
		t1 := FromSeconds(1000)
		t2 := FromSeconds(2000)

		assert.True(t, t1.Before(t2))
		assert.True(t, t2.After(t1))
		assert.False(t, t1.Equal(t2))
	})

	t.Run("equal", func(t *testing.T) {
		t1 := FromSeconds(1000)
		t2 := FromSeconds(1000)

		assert.True(t, t1.Equal(t2))
		assert.True(t, t2.Equal(t1))
	})
}

func TestJamTimeArithmetic(t *testing.T) {
	t.Run("adding jamtime", func(t *testing.T) {
		t1 := FromSeconds(1000)
		duration := 500 * time.Second

		t2 := t1.Add(duration)
		assert.False(t, t2.Equal(t1))
		assert.NotEqual(t, t2.Seconds, t1.Seconds)
	})

	t.Run("subbing jamtime", func(t *testing.T) {
		t1 := FromSeconds(1000)
		t2 := FromSeconds(500)

		duration := t1.Sub(t2)
		assert.Equal(t, time.Duration(500)*time.Second, duration)
	})
}

func TestJamTime_MarshalJSON(t *testing.T) {
	t.Run("successfully marshal to json", func(t *testing.T) {
		jamTime := FromSeconds(1000)
		jsonData, err := json.Marshal(jamTime)
		require.NoError(t, err)

		expected := []byte(`"2024-01-01T12:16:40Z"`)

		assert.Equal(t, expected, jsonData)
	})
}

func TestJamTime_UnmarshalJSON(t *testing.T) {
	t.Run("successfully unmarshal jamtime", func(t *testing.T) {
		jsonData := []byte(`"2024-01-01T12:00:00Z"`)

		var unmarshaledTime JamTime
		err := json.Unmarshal(jsonData, &unmarshaledTime)
		require.NoError(t, err)

		got := unmarshaledTime.ToTime()

		assert.True(t, got.Equal(JamEpoch))
	})

	t.Run("successfully unmarshal jamtime in future", func(t *testing.T) {
		jsonData := []byte(`"2024-01-01T12:00:01Z"`)
		want := JamEpoch.Add(1 * time.Second)

		var unmarshaledTime JamTime
		err := json.Unmarshal(jsonData, &unmarshaledTime)
		require.NoError(t, err)

		got := unmarshaledTime.ToTime()
		assert.True(t, got.Equal(want))
	})

	t.Run("errors when unmarshalling unknown data structure", func(t *testing.T) {
		jsonData := []byte(`asdasdasd`)
		var unmarshaledTime JamTime

		err := unmarshaledTime.UnmarshalJSON(jsonData)
		assert.Error(t, err)

		assert.EqualError(t, err, `parsing time "asdasdasd" as "\"2006-01-02T15:04:05Z07:00\"": cannot parse "asdasdasd" as "\""`)
	})
}

func TestJamTimeFromToTimeslotConversion(t *testing.T) {
	t.Run("convert jamtime to timeslot", func(t *testing.T) {
		jamTime := FromSeconds(3600) // 10 minutes after JAM Epoch
		timeslot := jamTime.ToTimeslot()

		expected := Timeslot(600)
		assert.Equal(t, expected, timeslot)
	})

	t.Run("convert timeslot to jamtime", func(t *testing.T) {
		slot := Timeslot(100)

		jamTime := FromTimeslot(slot)
		expected := uint64(600)
		assert.Equal(t, expected, jamTime.Seconds)
	})
}

func TestJamTime_IsInFutureTimeSlot(t *testing.T) {
	currentTime := Now()
	pastTime := currentTime.Add(-5 * time.Minute)
	futureTime := currentTime.Add(10 * time.Minute)

	assert.False(t, currentTime.IsInFutureTimeSlot())
	assert.False(t, pastTime.IsInFutureTimeSlot())
	assert.True(t, futureTime.IsInFutureTimeSlot())
}

func TestJamTime_ToEpoch(t *testing.T) {
	t.Run("jamtime to epoch", func(t *testing.T) {
		jamTime := FromSeconds(3600) // 1 hour after JAM Epoch
		epoch := jamTime.ToEpoch()
		expected := Epoch(1)
		assert.Equal(t, expected, epoch)
	})
}

func TestJamTech_FromEpoch(t *testing.T) {
	t.Run("epoch to jamtime", func(t *testing.T) {
		e := Epoch(1)

		convertedJamTime := FromEpoch(e)

		assert.Equal(t, uint64(3600), convertedJamTime.Seconds)
	})
}

func TestEpochAndTimeslotConversion(t *testing.T) {
	t.Run("successfully converts jamtime to epoch and timeslot", func(t *testing.T) {
		jamTime := FromSeconds(3600) // 1 hour after JAM Epoch

		epoch, timeslot := jamTime.ToEpochAndTimeslot()
		expectedEpoch := Epoch(1)
		expectedTimeslot := Timeslot(0)

		assert.Equal(t, expectedEpoch, epoch)
		assert.Equal(t, expectedTimeslot, timeslot)
	})

	t.Run("successfully converts epoch and timeslot to jamtime", func(t *testing.T) {
		timeslot := Timeslot(1)
		epoch := Epoch(1)

		jamTime, err := EpochAndTimeslotToJamTime(epoch, timeslot)
		require.NoError(t, err)

		expected := uint64(3606)

		assert.Equal(t, expected, jamTime.Seconds)
	})

	t.Run("returns an error when timeslot is outside of accepted range", func(t *testing.T) {
		timeslot := Timeslot(601)
		epoch := Epoch(1)

		jamTime, err := EpochAndTimeslotToJamTime(epoch, timeslot)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrTimeslotExceedsEpochLength)
		assert.True(t, jamTime.IsZero())
	})
}

func TestValidateJamTime(t *testing.T) {
	t.Run("today is valid", func(t *testing.T) {
		now := time.Now()

		err := ValidateJamTime(now)
		assert.NoError(t, err)
	})

	t.Run("the future should be valid", func(t *testing.T) {
		validTime := time.Date(2500, time.July, 27, 0, 0, 0, 0, time.UTC)

		err := ValidateJamTime(validTime)
		assert.NoError(t, err)
	})

	t.Run("far into the future should be invalid", func(t *testing.T) {
		inValidTime := time.Date(2840, time.August, 31, 23, 59, 59, 999999999, time.UTC)

		err := ValidateJamTime(inValidTime)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrAfterMaxJamTime)
	})

	t.Run("date before January 1st 2024 is invalid", func(t *testing.T) {
		invalidTime := time.Date(2023, time.December, 31, 0, 0, 0, 0, time.UTC)
		err := ValidateJamTime(invalidTime)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrBeforeJamEpoch)
	})
}

func TestJamTime_IsInSameEpoch(t *testing.T) {
	t.Run("same epoch - beginning", func(t *testing.T) {
		time1 := JamTime{Seconds: 0}
		time2 := JamTime{Seconds: 3599}

		assert.True(t, time1.IsInSameEpoch(time2))
	})

	t.Run("same epoch - middle", func(t *testing.T) {
		time1 := JamTime{Seconds: 3600*100 + 1800}
		time2 := JamTime{Seconds: 3600*100 + 3599}

		assert.True(t, time1.IsInSameEpoch(time2))
	})

	t.Run("different epochs - consecutive", func(t *testing.T) {
		time1 := JamTime{Seconds: 3599}
		time2 := JamTime{Seconds: 3600}

		assert.False(t, time1.IsInSameEpoch(time2))
	})

	t.Run("different epochs - far apart", func(t *testing.T) {
		time1 := JamTime{Seconds: 3600 * 100}
		time2 := JamTime{Seconds: 3600 * 200}

		assert.False(t, time1.IsInSameEpoch(time2))
	})

	t.Run("same time", func(t *testing.T) {
		time1 := JamTime{Seconds: 3600 * 50}

		assert.True(t, time1.IsInSameEpoch(time1))
	})

	t.Run("epoch boundary - end of epoch", func(t *testing.T) {
		time1 := JamTime{Seconds: 3600 - 1}
		time2 := JamTime{Seconds: 3600}

		assert.False(t, time1.IsInSameEpoch(time2))
	})

	t.Run("epoch boundary - start of epoch", func(t *testing.T) {
		time1 := JamTime{Seconds: 3600}
		time2 := JamTime{Seconds: 3600 + 1}

		assert.True(t, time1.IsInSameEpoch(time2))
	})

	t.Run("max time value", func(t *testing.T) {
		maxTime := JamTime{Seconds: ^uint64(0)}
		almostMaxTime := JamTime{Seconds: ^uint64(0) - 3599}

		assert.True(t, maxTime.IsInSameEpoch(almostMaxTime))
	})

	t.Run("zero and almost one epoch", func(t *testing.T) {
		time1 := JamTime{Seconds: 0}
		time2 := JamTime{Seconds: 3599}

		assert.True(t, time1.IsInSameEpoch(time2))
	})
}
