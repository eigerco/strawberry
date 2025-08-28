//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/common"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/jamtime"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type StatisticsJSONData struct {
	Input     StatisticsInput `json:"input"`
	PreState  StatisticsState `json:"pre_state"`
	PostState StatisticsState `json:"post_state"`
}

type StatisticsState struct {
	Pi         Pi               `json:"pi"`
	Tau        jamtime.Timeslot `json:"tau"`
	KappaPrime []ValidatorKey   `json:"kappa_prime"`
}

type Pi struct {
	ValsCurrent []PiData `json:"current"`
	ValsLast    []PiData `json:"last"`
}

type PiData struct {
	Blocks        uint32 `json:"blocks"`
	Tickets       uint32 `json:"tickets"`
	PreImages     uint32 `json:"pre_images"`
	PreImagesSize uint32 `json:"pre_images_size"`
	Guarantees    uint32 `json:"guarantees"`
	Assurances    uint32 `json:"assurances"`
}

type StatisticsInput struct {
	Extrinsic   Extrinsic        `json:"extrinsic"`
	Reporters   []string         `json:"reporters"`
	Slot        jamtime.Timeslot `json:"slot"`
	AuthorIndex uint16           `json:"author_index"`
}

type Extrinsic struct {
	Assurances []Assurance `json:"assurances"`
	Tickets    []Ticket    `json:"tickets"`
	Preimages  []Preimage  `json:"preimages"`
	Guarantees []Guarantee `json:"guarantees"`
	Disputes   Disputes    `json:"disputes"`
}
type Ticket struct {
	Attempt   uint8  `json:"attempt"`
	Signature string `json:"signature"`
}
type Preimage struct {
	Requester uint32 `json:"requester"`
	Blob      string `json:"blob"`
}

func ReadStatisticsJSONFile(filename string) (*StatisticsJSONData, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	bytes, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	var data StatisticsJSONData
	if err := json.Unmarshal(bytes, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	return &data, nil
}

func mapStatisticsInput(s StatisticsInput) block.Block {
	return block.Block{
		Header: block.Header{
			TimeSlotIndex:    s.Slot,
			BlockAuthorIndex: s.AuthorIndex,
		},
		Extrinsic: block.Extrinsic{
			ET: block.TicketExtrinsic{
				TicketProofs: mapSlice(s.Extrinsic.Tickets, func(t Ticket) block.TicketProof {
					return block.TicketProof{
						EntryIndex: t.Attempt,
						Proof:      [784]byte(mustStringToHex(t.Signature)),
					}
				}),
			},
			EP: mapSlice(s.Extrinsic.Preimages, func(p Preimage) block.Preimage {
				return block.Preimage{
					ServiceIndex: p.Requester,
					Data:         mustStringToHex(p.Blob),
				}
			}),
			EG: block.GuaranteesExtrinsic{
				Guarantees: mapSlice(s.Extrinsic.Guarantees, func(g Guarantee) block.Guarantee {
					return block.Guarantee{
						WorkReport: block.WorkReport{},
						Timeslot:   0,
						Credentials: mapSlice(g.Signatures, func(sig Signature) block.CredentialSignature {
							return block.CredentialSignature{
								ValidatorIndex: sig.ValidatorIndex,
								Signature:      crypto.Ed25519Signature(mustStringToHex(sig.Signature)),
							}
						}),
					}
				}),
			},
			EA: mapSlice(s.Extrinsic.Assurances, func(a Assurance) block.Assurance {
				return block.Assurance{
					Anchor:         mapHash(a.Anchor),
					Bitfield:       [block.AvailBitfieldBytes]byte(mustStringToHex(a.Bitfield)),
					ValidatorIndex: a.ValidatorIndex,
					Signature:      crypto.Ed25519Signature(mustStringToHex(a.Signature)),
				}
			}),
			ED: mapDisputes(s.Extrinsic.Disputes),
		},
	}
}

func mapStatisticsState(s StatisticsState) state.State {
	return state.State{
		ActivityStatistics: validator.ActivityStatisticsState{
			ValidatorsLast: [common.NumberOfValidators]validator.ValidatorStatistics(mapSlice(s.Pi.ValsLast, func(pi PiData) validator.ValidatorStatistics {
				return validator.ValidatorStatistics{
					NumOfBlocks:                 pi.Blocks,
					NumOfTickets:                pi.Tickets,
					NumOfPreimages:              pi.PreImages,
					NumOfBytesAllPreimages:      pi.PreImagesSize,
					NumOfGuaranteedReports:      pi.Guarantees,
					NumOfAvailabilityAssurances: pi.Assurances,
				}
			})),
			ValidatorsCurrent: [common.NumberOfValidators]validator.ValidatorStatistics(mapSlice(s.Pi.ValsCurrent, func(pi PiData) validator.ValidatorStatistics {
				return validator.ValidatorStatistics{
					NumOfBlocks:                 pi.Blocks,
					NumOfTickets:                pi.Tickets,
					NumOfPreimages:              pi.PreImages,
					NumOfBytesAllPreimages:      pi.PreImagesSize,
					NumOfGuaranteedReports:      pi.Guarantees,
					NumOfAvailabilityAssurances: pi.Assurances,
				}
			})),
		},
		TimeslotIndex: s.Tau,
		ValidatorState: validator.ValidatorState{
			CurrentValidators: mapCurrValidators(s.KappaPrime),
		},
	}
}

func TestStatistics(t *testing.T) {
	files, err := os.ReadDir(fmt.Sprintf("vectors/statistics/%s", vectorsType))
	require.NoError(t, err, "failed to read directory: vectors/statistics/%s')", vectorsType)
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		t.Run(file.Name(), func(t *testing.T) {
			filePath := fmt.Sprintf("vectors/statistics/%s/%s", vectorsType, file.Name())
			tc, err := ReadStatisticsJSONFile(filePath)
			require.NoError(t, err, "failed to read JSON file: %s", filePath)
			newBlock := mapStatisticsInput(tc.Input)
			preState := mapStatisticsState(tc.PreState)
			reporters := make(crypto.ED25519PublicKeySet)
			for _, reporter := range tc.Input.Reporters {
				reporters.Add(mustStringToHex(reporter))
			}

			preState.ActivityStatistics = statetransition.CalculateNewActivityStatistics(newBlock, preState.TimeslotIndex, preState.ActivityStatistics, reporters, preState.ValidatorState.CurrentValidators,
				[]block.WorkReport{}, statetransition.AccumulationStats{}, statetransition.DeferredTransfersStats{})

			postState := mapStatisticsState(tc.PostState)

			assert.Equal(t, postState.ActivityStatistics.ValidatorsCurrent, preState.ActivityStatistics.ValidatorsCurrent)
			assert.Equal(t, postState.ActivityStatistics.ValidatorsLast, preState.ActivityStatistics.ValidatorsLast)
		})
	}
}
