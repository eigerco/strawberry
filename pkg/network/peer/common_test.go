package peer_test

import (
	"crypto/ed25519"
	"testing"

	"github.com/eigerco/strawberry/pkg/network/peer"

	"github.com/stretchr/testify/require"
)

func newTestPeer(key ed25519.PublicKey, validatorIndex *uint16) *peer.Peer {
	return &peer.Peer{
		Ed25519Key:     key,
		ValidatorIndex: validatorIndex,
	}
}

func TestMergeValidators(t *testing.T) {
	k1, _, _ := ed25519.GenerateKey(nil)
	k2, _, _ := ed25519.GenerateKey(nil)
	k3, _, _ := ed25519.GenerateKey(nil)
	k4, _, _ := ed25519.GenerateKey(nil)

	i1, i2, i3 := uint16(1), uint16(2), uint16(3)

	tests := []struct {
		name     string
		a        []*peer.Peer
		b        []*peer.Peer
		expected []ed25519.PublicKey
	}{
		{
			name:     "empty inputs",
			a:        nil,
			b:        nil,
			expected: nil,
		},
		{
			name:     "only validators from A",
			a:        []*peer.Peer{newTestPeer(k1, &i1), newTestPeer(k2, &i2)},
			b:        nil,
			expected: []ed25519.PublicKey{k1, k2},
		},
		{
			name:     "only validators from B",
			a:        nil,
			b:        []*peer.Peer{newTestPeer(k1, &i1), newTestPeer(k2, &i2)},
			expected: []ed25519.PublicKey{k1, k2},
		},
		{
			name: "merge with duplicates",
			a:    []*peer.Peer{newTestPeer(k1, &i1), newTestPeer(k2, &i2)},
			b:    []*peer.Peer{newTestPeer(k1, &i1), newTestPeer(k2, &i2), newTestPeer(k3, &i3)},
			expected: []ed25519.PublicKey{
				k1, k2, k3,
			},
		},
		{
			name: "ignore non validators",
			a: []*peer.Peer{
				newTestPeer(k1, &i1),
				newTestPeer(k4, nil), // ignored
			},
			b: []*peer.Peer{
				newTestPeer(k2, &i2),
				newTestPeer(k4, nil), // ignored
			},
			expected: []ed25519.PublicKey{k1, k2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := peer.MergeValidators(tt.a, tt.b)

			require.Equal(t, len(tt.expected), len(result))
			for i, expectedKey := range tt.expected {
				require.Equal(t, expectedKey, result[i].Ed25519Key)
			}
		})
	}
}
