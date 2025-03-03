//go:build integration

package integration_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"
	"github.com/stretchr/testify/require"
)

func TestBlockSealCommunityVectors(t *testing.T) {
	testFiles := []string{
		"vectors_community/sealing/0-0.json",
		"vectors_community/sealing/0-1.json",
		"vectors_community/sealing/0-2.json",
		"vectors_community/sealing/0-4.json",
		"vectors_community/sealing/0-5.json",
		"vectors_community/sealing/1-0.json",
		"vectors_community/sealing/1-1.json",
		"vectors_community/sealing/1-2.json",
		"vectors_community/sealing/1-3.json",
		"vectors_community/sealing/1-4.json",
		"vectors_community/sealing/1-5.json",
	}

	for _, tf := range testFiles {
		t.Run(filepath.Base(tf), func(t *testing.T) {
			file, err := os.ReadFile(tf)
			require.NoError(t, err)

			var tv blockSealTestData
			err = json.Unmarshal(file, &tv)
			require.NoError(t, err)

			var header block.Header
			headerBytes := testutils.MustFromHex(t, tv.HeaderBytes)
			err = jam.Unmarshal(headerBytes, &header)
			require.NoError(t, err)

			privateKey := crypto.BandersnatchPrivateKey(testutils.MustFromHex(t, tv.BandersnatchPriv))
			entropy := crypto.Hash(testutils.MustFromHex(t, tv.Eta3))

			var ticketOrKey state.TicketOrKey
			if tv.T == 1 {
				ticketOrKey = block.Ticket{
					Identifier: crypto.BandersnatchOutputHash(testutils.MustFromHex(t, tv.TicketID)),
					EntryIndex: tv.Attempt,
				}
			} else { // Fallback case.
				ticketOrKey = crypto.BandersnatchPublicKey(testutils.MustFromHex(t, tv.BandersnatchPub))
			}

			sealSignature, vrfsSignature, err := state.SignBlock(header, ticketOrKey, privateKey, entropy)
			require.NoError(t, err)

			require.Equal(t, hex.EncodeToString(sealSignature[:]), tv.Hs)
			require.Equal(t, hex.EncodeToString(vrfsSignature[:]), tv.Hv)
		})
	}
}

type blockSealTestData struct {
	BandersnatchPub  string `json:"bandersnatch_pub"`
	BandersnatchPriv string `json:"bandersnatch_priv"`
	TicketID         string `json:"ticket_id"`
	Attempt          uint8  `json:"attempt"`
	CForHs           string `json:"c_for_H_s"`
	MForHs           string `json:"m_for_H_s"`
	Hs               string `json:"H_s"`
	CForHv           string `json:"c_for_H_v"`
	MForHv           string `json:"m_for_H_v"`
	Hv               string `json:"H_v"`
	Eta3             string `json:"eta3"`
	T                int    `json:"T"`
	HeaderBytes      string `json:"header_bytes"`
}
