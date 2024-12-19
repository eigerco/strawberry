package protocol

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestProtocolIDString(t *testing.T) {
	testCases := []struct {
		name     string
		input    *ProtocolID
		expected string
	}{
		{
			name: "Regular Protocol",
			input: &ProtocolID{
				Version:   currentVersion,
				ChainHash: "abcd1234",
				IsBuilder: false,
			},
			expected: "jamnp-s/" + currentVersion + "/abcd1234",
		},
		{
			name: "Builder Protocol",
			input: &ProtocolID{
				Version:   currentVersion,
				ChainHash: "abcd1234",
				IsBuilder: true,
			},
			expected: "jamnp-s/" + currentVersion + "/abcd1234/builder",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.input.String()
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestParseProtocolID_Valid(t *testing.T) {
	validTestCases := []struct {
		name     string
		input    string
		expected *ProtocolID
	}{
		{
			name:  "Regular Protocol",
			input: "jamnp-s/" + currentVersion + "/abcd1234",
			expected: &ProtocolID{
				Version:   currentVersion,
				ChainHash: "abcd1234",
				IsBuilder: false,
			},
		},
		{
			name:  "Builder Protocol",
			input: "jamnp-s/" + currentVersion + "/abcd1234/builder",
			expected: &ProtocolID{
				Version:   currentVersion,
				ChainHash: "abcd1234",
				IsBuilder: true,
			},
		},
	}

	for _, tc := range validTestCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseProtocolID(tc.input)
			require.NoError(t, err, "Expected no error for valid input")
			assert.Equal(t, tc.expected.Version, result.Version, "Version mismatch")
			assert.Equal(t, tc.expected.ChainHash, result.ChainHash, "ChainHash mismatch")
			assert.Equal(t, tc.expected.IsBuilder, result.IsBuilder, "IsBuilder mismatch")
		})
	}
}

func TestParseProtocolID_Invalid(t *testing.T) {
	invalidTestCases := []struct {
		name          string
		input         string
		expectedError string
	}{
		{name: "Empty String", input: "", expectedError: "invalid protocol format"},
		{name: "Invalid Prefix", input: "invalid/" + currentVersion + "/abcd1234", expectedError: "invalid protocol prefix"},
		{name: "Invalid Version", input: "jamnp-s/99/abcd1234", expectedError: "unsupported protocol version"},
		{name: "Invalid Chain Hash Length", input: "jamnp-s/" + currentVersion + "/abc123", expectedError: "invalid chain hash length"},
		{name: "Invalid Chain Hash Characters", input: "jamnp-s/" + currentVersion + "/abcdxxxx", expectedError: "invalid chain hash character"},
		{name: "Invalid Builder Suffix", input: "jamnp-s/" + currentVersion + "/abcd1234/invalid", expectedError: "invalid protocol suffix"},
		{name: "Too Many Parts", input: "jamnp-s/" + currentVersion + "/abcd1234/builder/extra", expectedError: "invalid protocol format"},
	}

	for _, tc := range invalidTestCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseProtocolID(tc.input)
			require.Error(t, err, "Expected error for invalid input")
			assert.Contains(t, err.Error(), tc.expectedError, "Unexpected error message")
		})
	}
}

func TestAcceptableProtocols(t *testing.T) {
	chainHash := "abcd1234"
	expected := []string{
		"jamnp-s/" + currentVersion + "/abcd1234",
		"jamnp-s/" + currentVersion + "/abcd1234/builder",
	}

	result := AcceptableProtocols(chainHash)
	assert.Equal(t, expected, result, "acceptable protocols should match expected list")
}

func TestValidateALPNProtocol_Valid(t *testing.T) {
	validProtocols := []string{
		"jamnp-s/" + currentVersion + "/abcd1234",
		"jamnp-s/" + currentVersion + "/abcd1234/builder",
		"jamnp-s/" + currentVersion + "/deadbeef",
		"jamnp-s/" + currentVersion + "/deadbeef/builder",
	}

	for _, protocol := range validProtocols {
		t.Run("Valid: "+protocol, func(t *testing.T) {
			err := ValidateALPNProtocol(protocol)
			assert.NoError(t, err, "Expected protocol to be valid: %s", protocol)
		})
	}
}

func TestValidateALPNProtocol_Invalid(t *testing.T) {
	invalidProtocols := []string{
		"",
		"jamnp-s",
		"jamnp-s/" + currentVersion + "",
		"jamnp-s/99/abcd1234",
		"jamnp-s/" + currentVersion + "/abcd123",
		"jamnp-s/" + currentVersion + "/abcd123g",
		"jamnp-s/" + currentVersion + "/abcd1234/invalid",
		"invalid/" + currentVersion + "/abcd1234",
	}

	for _, protocol := range invalidProtocols {
		t.Run("Invalid: "+protocol, func(t *testing.T) {
			err := ValidateALPNProtocol(protocol)
			assert.Error(t, err, "Expected protocol to be invalid: %s", protocol)
		})
	}
}
