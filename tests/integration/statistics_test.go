//go:build integration

package integration

import (
	"embed"
	"encoding/json"
	"io"
	"path"
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

//go:embed vectors/statistics
var statisticstestvectors embed.FS

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
type Guarantee struct {
	Report     Report      `json:"report"`
	Slot       int         `json:"slot"`
	Signatures []Signature `json:"signatures"`
}

type Signature struct {
	ValidatorIndex uint16 `json:"validator_index"`
	Signature      string `json:"signature"`
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
	rootPath := "vectors/statistics/tiny"
	ff, err := statisticstestvectors.ReadDir(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range ff {
		t.Run(file.Name(), func(t *testing.T) {
			tc := &StatisticsJSONData{}
			f, err := statisticstestvectors.Open(path.Join(rootPath, file.Name()))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = f.Close()
			})
			bb, err := io.ReadAll(f)
			require.NoError(t, err)

			if err := json.Unmarshal(bb, tc); err != nil {
				t.Fatal(err)
			}
			newBlock := mapStatisticsInput(tc.Input)
			preState := mapStatisticsState(tc.PreState)
			reporters := make(crypto.ED25519PublicKeySet)
			for _, reporter := range tc.Input.Reporters {
				reporters.Add(mustStringToHex(reporter))
			}

			preState.ActivityStatistics = statetransition.CalculateNewActivityStatistics(newBlock, preState.TimeslotIndex, preState.ActivityStatistics, reporters, preState.ValidatorState.CurrentValidators)

			postState := mapStatisticsState(tc.PostState)

			assert.Equal(t, postState, preState)
		})
	}
}
