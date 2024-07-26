package tests

import (
	"encoding/json"
	"github.com/ChainSafe/gossamer/pkg/scale"
	"github.com/eigerco/strawberry/internal/safrole"
	"os"
	"testing"
)

func TestScaleDecode(t *testing.T) {
	// 1. Read scale file
	b, err := os.ReadFile("vectors/enact-epoch-change-with-no-tickets-1.scale")
	if err != nil {
		t.Errorf("Failed to read scale file: %v", err)
	}

	// Unmarshal the .scale file
	var unmarshaled safrole.Safrole
	err = scale.Unmarshal(b, &unmarshaled)
	if err != nil {
		t.Errorf("Failed to unmarshal scale file: %v", err)
	}

	if unmarshaled.Input.Extrinsic == nil {
		unmarshaled.Input.Extrinsic = []safrole.TicketEnvelope{}
	}

	if unmarshaled.PreState.GammaA == nil {
		unmarshaled.PreState.GammaA = []safrole.TicketBody{}
	}
	if unmarshaled.PostState.GammaA == nil {
		unmarshaled.PostState.GammaA = []safrole.TicketBody{}
	}

	// Marshal the unmarshaled scale data to JSON
	jsonData, err := json.MarshalIndent(unmarshaled, "", "  ")
	if err != nil {
		t.Errorf("Failed to json marshal the unmarshalled scale file: %v", err)
	}

	// Write the JSON data to a file
	err = os.WriteFile("output.json", jsonData, 0644)
	if err != nil {
		t.Errorf("Failed to write JSON file: %v", err)
	}

	// Read the expected JSON file
	expectedData, err := os.ReadFile("vectors/enact-epoch-change-with-no-tickets-1.json")
	if err != nil {
		t.Errorf("Failed to read expected JSON file: %v", err)
	}

	// Unmarshal both JSON files into interface{}
	var actual interface{}
	var expected interface{}

	err = json.Unmarshal(jsonData, &actual)
	if err != nil {
		t.Errorf("Failed to unmarshal output JSON data: %v", err)
	}

	err = json.Unmarshal(expectedData, &expected)
	if err != nil {
		t.Errorf("Failed to unmarshal expected JSON data: %v", err)
	}

	// Marshal both interfaces back to JSON
	actualNormalized, err := json.Marshal(actual)
	if err != nil {
		t.Errorf("Failed to marshal actual JSON data: %v", err)
	}

	expectedNormalized, err := json.Marshal(expected)
	if err != nil {
		t.Errorf("Failed to marshal expected JSON data: %v", err)
	}

	// Compare the normalized JSON strings
	if string(actualNormalized) != string(expectedNormalized) {
		t.Errorf("The output JSON does not match the expected JSON")
	}
}
