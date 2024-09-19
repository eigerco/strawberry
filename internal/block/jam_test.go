package block

import (
	"encoding/json"
	"fmt"
	"github.com/eigerco/strawberry/pkg/serialization"
	"github.com/eigerco/strawberry/pkg/serialization/codec"
	"os"
	"testing"
)

func TestJamDecode(t *testing.T) {
	fileNames := []string{
		"header_0",
		"header_1",
	}

	for _, f := range fileNames {
		t.Run(f, func(t *testing.T) {
			// 1. Read scale file
			b, err := os.ReadFile(fmt.Sprintf("vectors/%s.bin", f))
			if err != nil {
				t.Errorf("Failed to read scale file: %v", err)
			}

			s := serialization.NewSerializer(codec.NewJamCodec())

			var unmarshaled Header
			err = s.Decode(b, &unmarshaled)
			if err != nil {
				t.Errorf("Failed to unmarshal binary file: %v", err)
			}

			jsonData, err := json.MarshalIndent(unmarshaled, "", "  ")
			if err != nil {
				t.Errorf("Failed to json marshal the unmarshalled jam file: %v", err)
			}

			err = createDirIfNotExists("generated")
			if err != nil {
				t.Fatalf("Failed to create folder: %v", err)
			}
			// Write the JSON data to a file
			err = os.WriteFile(fmt.Sprintf("generated/%s.output.json", f), jsonData, 0644)
			if err != nil {
				t.Errorf("Failed to write JSON file: %v", err)
			}
		})
	}
}

func TestJamDecodeBlock(t *testing.T) {
	fileNames := []string{
		"block",
	}

	for _, f := range fileNames {
		t.Run(f, func(t *testing.T) {
			// 1. Read scale file
			b, err := os.ReadFile(fmt.Sprintf("vectors/%s.bin", f))
			if err != nil {
				t.Errorf("Failed to read scale file: %v", err)
			}

			s := serialization.NewSerializer(codec.NewJamCodec())

			var unmarshaled Block
			err = s.Decode(b, &unmarshaled)
			if err != nil {
				t.Errorf("Failed to unmarshal binary file: %v", err)
			}

			//fmt.Println(unmarshaled.Extrinsic.EG.Guarantees[0].WorkReport.WorkResults[0].Output.inner)
			//fmt.Println(fmt.Sprintf("0x%x", unmarshaled.Extrinsic.EG.Guarantees[0].WorkReport.Output))
			//fmt.Println(fmt.Sprintf("0x%x", unmarshaled.Extrinsic.EP[0].Data))

			jsonData, err := json.MarshalIndent(unmarshaled, "", "  ")
			if err != nil {
				t.Errorf("Failed to json marshal the unmarshalled jam file: %v", err)
			}

			err = createDirIfNotExists("generated")
			if err != nil {
				t.Fatalf("Failed to create folder: %v", err)
			}
			// Write the JSON data to a file
			err = os.WriteFile(fmt.Sprintf("generated/%s.output.json", f), jsonData, 0644)
			if err != nil {
				t.Errorf("Failed to write JSON file: %v", err)
			}
		})
	}
}

func createDirIfNotExists(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.Mkdir(dir, os.ModePerm); err != nil {
			return err
		}
	}
	return nil
}
