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
		jamTime, err := FromTime(standardTime)
		assert.Nil(t, err)
		convertedTime := jamTime.ToTime()
		assert.True(t, standardTime.Equal(convertedTime))
	})

	t.Run("converts correct JamEpoch to JamTime", func(t *testing.T) {
		jamEpoch, err := FromTime(JamEpoch)
		assert.Nil(t, err)
		assert.EqualValues(t, 0, jamEpoch.Seconds)
	})

	t.Run("converts time between JamEpoch and MaxJamTime to JamTime correctly", func(t *testing.T) {
		expected := MaxRepresentableJamTime.Add(-1 * time.Hour)
		jt, err := FromTime(expected)
		assert.Nil(t, err)
		got := jt.ToTime()
		assert.True(t, expected.Equal(got))
	})

	t.Run("fails to convert time.Time past MaxJamTime to JamTime", func(t *testing.T) {
		year3000 := time.Date(3000, time.March, 15, 12, 0, 0, 0, time.UTC)
		jamTime, err := FromTime(year3000)
		assert.NotNil(t, err)

		assert.True(t, jamTime.IsZero())
	})

	t.Run("fails to convert time.Time from the past", func(t *testing.T) {
		year2000 := time.Date(2000, time.March, 15, 12, 0, 0, 0, time.UTC)
		jamTime, err := FromTime(year2000)
		assert.NotNil(t, err)
		assert.ErrorIs(t, err, ErrBeforeJamEpoch)

		assert.True(t, jamTime.IsZero())
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

func TestJamTime_ToTime(t *testing.T) {
	t.Run("converts JamEpoch to and from time.Time", func(t *testing.T) {
		start, err := FromTime(JamEpoch)
		assert.Nil(t, err)
		assert.EqualValues(t, 0, start.Seconds)
		got := start.ToTime()
		assert.Equal(t, JamEpoch, got)
	})

	t.Run("converts time.Time to jamTime and back", func(t *testing.T) {
		in := time.Date(2025, 07, 27, 01, 01, 00, 00, time.UTC)
		jt, err := FromTime(in)
		assert.Nil(t, err)

		got := jt.ToTime()
		assert.True(t, in.Equal(got))
	})

	t.Run("converts MaxRepresentableJamTime to and from time.Time", func(t *testing.T) {
		in := MaxRepresentableJamTime
		start, err := FromTime(in)
		assert.Nil(t, err)

		got := start.ToTime()
		assert.Equal(t, MaxRepresentableJamTime, got)
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

		t2, err := t1.Add(duration)
		assert.Nil(t, err)
		assert.False(t, t2.Equal(t1))
		assert.NotEqual(t, t2.Seconds, t1.Seconds)
	})

	t.Run("subbing time from jamtime epoch", func(t *testing.T) {
		t1, err := FromTime(JamEpoch)
		assert.Nil(t, err)
		duration := time.Duration(-500 * time.Second)

		got, err := t1.Add(duration)
		assert.NotNil(t, err)
		assert.ErrorIs(t, err, ErrBeforeJamEpoch)
		assert.True(t, got.IsZero())
	})

	t.Run("adding past max jamtime", func(t *testing.T) {
		t1, err := FromTime(MaxRepresentableJamTime)
		assert.Nil(t, err)
		duration := time.Duration(500 * time.Second)
		got, err := t1.Add(duration)
		assert.NotNil(t, err)
		assert.ErrorIs(t, err, ErrAfterMaxJamTime)
		assert.True(t, got.IsZero())
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

		expected := []byte(`"2025-01-01T12:16:40Z"`)

		assert.Equal(t, expected, jsonData)
	})
}

func TestJamTime_UnmarshalJSON(t *testing.T) {
	t.Run("successfully unmarshal jamtime", func(t *testing.T) {
		jsonData := []byte(`"2025-01-01T12:00:00Z"`)

		var unmarshaledTime JamTime
		err := json.Unmarshal(jsonData, &unmarshaledTime)
		require.NoError(t, err)

		got := unmarshaledTime.ToTime()

		assert.True(t, got.Equal(JamEpoch))
	})

	t.Run("successfully unmarshal jamtime in future", func(t *testing.T) {
		jsonData := []byte(`"2025-01-01T12:00:01Z"`)
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
	pastTime, err := currentTime.Add(-5 * time.Minute)
	assert.Nil(t, err)
	futureTime, err := currentTime.Add(10 * time.Minute)
	assert.Nil(t, err)

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
		inValidTime := time.Date(2841, time.August, 31, 23, 59, 59, 999999999, time.UTC)

		err := ValidateJamTime(inValidTime)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrAfterMaxJamTime)
	})

	t.Run("date before January 1st 2025 is invalid", func(t *testing.T) {
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

		assert.False(t, maxTime.IsInSameEpoch(almostMaxTime))
	})

	t.Run("zero and almost one epoch", func(t *testing.T) {
		time1 := JamTime{Seconds: 0}
		time2 := JamTime{Seconds: 3599}

		assert.True(t, time1.IsInSameEpoch(time2))
	})
}

func TestJamTime_Now_AlwaysReturnsUTC(t *testing.T) {
	t.Run("Now returns UTC regardless of system timezone", func(t *testing.T) {
		// Save original now function
		originalNow := now
		defer func() { now = originalNow }()

		// Create a specific fixed time to test with
		fixedUTCTime := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)

		// Mock now to return that time but in NY timezone
		nyLoc, _ := time.LoadLocation("America/New_York")
		fixedNYTime := fixedUTCTime.In(nyLoc)

		now = fixedNYTime

		jamNow := Now()
		convertedTime := jamNow.ToTime()

		// Assert it's UTC
		assert.Equal(t, time.UTC, convertedTime.Location())
		// Assert the actual time instant is preserved
		assert.True(t, convertedTime.Equal(fixedUTCTime))
		// Verify that the NY time and UTC time represent the same instant
		assert.True(t, fixedNYTime.Equal(fixedUTCTime))
		// Verify the JAM time seconds calculation is correct.
		// JamTime.Seconds represents the number of seconds elapsed since the JAM epoch
		// (2025-01-01 12:00:00 UTC). This should be the same regardless of timezone.
		expectedSeconds := uint64(fixedUTCTime.Unix() - JamEpoch.Unix())
		assert.Equal(t, expectedSeconds, jamNow.Seconds)
	})

	t.Run("Now with default implementation returns UTC", func(t *testing.T) {
		// Test with the actual implementation
		jamNow := Now()
		convertedTime := jamNow.ToTime()

		// Verify it's in UTC
		assert.Equal(t, time.UTC, convertedTime.Location())

		// Verify the stored src is also in UTC
		if !jamNow.src.IsZero() {
			assert.Equal(t, time.UTC, jamNow.src.Location())
		}
	})
}

func TestJamTime_FromTime_ConvertsToUTC(t *testing.T) {
	t.Run("converts non-UTC time to UTC", func(t *testing.T) {
		// Create a time in a different timezone
		loc, _ := time.LoadLocation("America/New_York")
		nyTime := time.Date(2025, time.March, 15, 8, 0, 0, 0, loc)

		jamTime, err := FromTime(nyTime)
		assert.NoError(t, err)

		// The internal time should be in UTC
		convertedTime := jamTime.ToTime()
		assert.Equal(t, time.UTC, convertedTime.Location())

		// Should be the same instant
		assert.True(t, nyTime.Equal(convertedTime))
	})
}

func TestJamTime_UnmarshalJSON_HandlesNonUTC(t *testing.T) {
	t.Run("unmarshals non-UTC time string correctly", func(t *testing.T) {
		// JSON with timezone offset
		jsonData := []byte(`"2025-01-01T07:00:00-05:00"`)

		var unmarshaledTime JamTime
		err := json.Unmarshal(jsonData, &unmarshaledTime)
		require.NoError(t, err)

		got := unmarshaledTime.ToTime()
		assert.Equal(t, time.UTC, got.Location())
		assert.True(t, got.Equal(JamEpoch))
	})
}
