package handlers

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"github.com/stretchr/testify/mock"
	"testing"
	"time"

	"github.com/eigerco/strawberry/internal/testutils"
	"github.com/eigerco/strawberry/internal/validator"
	"github.com/eigerco/strawberry/pkg/network/cert"
	"github.com/eigerco/strawberry/pkg/network/protocol"
	"github.com/eigerco/strawberry/pkg/network/transport"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShardDistHandler(t *testing.T) {
	erasureRoot := testutils.RandomHash(t)
	shardIndex := uint16(4)
	expectedBundleShard := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	expectedSegmentShard := [][]byte{
		{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		{13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24},
	}

	hash1 := testutils.RandomHash(t)
	hash2 := testutils.RandomHash(t)

	expectedJustification := [][]byte{hash1[:], hash2[:], append(hash1[:], hash2[:]...)}

	validatorService := validator.NewValidatorServiceMock()
	validatorService.ExpectedCalls = append(validatorService.ExpectedCalls, &mock.Call{
		Method:          "ShardDist",
		Arguments:       mock.Arguments{mock.Anything, erasureRoot, shardIndex},
		ReturnArguments: mock.Arguments{expectedBundleShard, expectedSegmentShard, expectedJustification, nil},
	})

	shardIndexBytes := make([]byte, 2)

	binary.LittleEndian.PutUint16(shardIndexBytes, shardIndex)

	AssertHandler(t, ShardDistHandler(validatorService), func(stream quic.Stream, ctx context.Context) {
		bundleShard, segmentShard, justification, err := CallShardDist(stream, ctx, erasureRoot, shardIndex)
		require.NoError(t, err)
		assert.Equal(t, expectedBundleShard, bundleShard)
		assert.Equal(t, expectedSegmentShard, segmentShard)
		assert.Equal(t, expectedJustification, justification)
	})
}

// AssertHandler sets up a quic server that accepts one stream and calls the provided handler
// dials and opens a stream then sends messages with the provided inputs and asserts the expected outputs
func AssertHandler(t *testing.T, handler protocol.StreamHandler, caller func(stream quic.Stream, ctx context.Context)) {
	t.Helper()

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tlsCert, err := cert.NewGenerator(cert.Config{
		PublicKey:          pubKey,
		PrivateKey:         privKey,
		CertValidityPeriod: 24 * time.Hour,
	}).GenerateCertificate()
	require.NoError(t, err)

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{*tlsCert},
		ClientAuth:         tls.RequireAnyClientCert,
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2) //
	t.Cleanup(cancel)

	done := make(chan struct{})
	addrCh := make(chan string)

	go func() {
		l, err := quic.ListenAddr("127.0.0.1:0000", tlsConfig, &quic.Config{
			EnableDatagrams: true,
			MaxIdleTimeout:  transport.MaxIdleTimeout,
		})
		require.NoError(t, err)
		addrCh <- l.Addr().String()

		conn, err := l.Accept(ctx)
		require.NoError(t, err)

		s, err := conn.AcceptStream(ctx)
		require.NoError(t, err)

		err = handler.HandleStream(ctx, s, pubKey)
		assert.NoError(t, err)
		done <- struct{}{}
	}()

	addr := <-addrCh
	conn, err := quic.DialAddr(ctx, addr, tlsConfig, &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  transport.MaxIdleTimeout,
	})
	require.NoError(t, err)
	s, err := conn.OpenStream()
	require.NoError(t, err)

	caller(s, ctx)

	<-done

	s.Close()
}
