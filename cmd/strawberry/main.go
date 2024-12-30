package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/eigerco/strawberry/pkg/network/cert"
	"github.com/eigerco/strawberry/pkg/network/handlers"
	"github.com/eigerco/strawberry/pkg/network/peer"
	"github.com/eigerco/strawberry/pkg/network/protocol"
	"github.com/eigerco/strawberry/pkg/network/transport"
)

// main starts a blockchain node.
//
// To run the first node (listener):
//
//	go run main.go -addr localhost:9000
//
// To run a second node that connects to the first node:
//
//	go run main.go -addr localhost:9001 -connect localhost:9000
//
// - The first node listens on port 9000.
// - The second node listens on port 9001 and connects to the first node's address (localhost:9000).
func main() {
	listenAddr := flag.String("addr", "", "Listen address (e.g., 0.0.0.0:9000)")
	connectTo := flag.String("connect", "", "Address to connect to (optional)")
	flag.Parse()

	if *listenAddr == "" {
		log.Fatal("listen address is required")
	}

	// Generate node keys
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatalf("Failed to generate keys: %v", err)
	}

	// Create certificate
	certGen := cert.NewGenerator(cert.Config{
		PublicKey:          pub,
		PrivateKey:         priv,
		CertValidityPeriod: 24 * time.Hour,
	})
	tlsCert, err := certGen.GenerateCertificate()
	if err != nil {
		log.Fatalf("Failed to generate certificate: %v", err)
	}

	// Create protocol manager
	protoConfig := protocol.Config{
		ChainHash:       "12345678", // Example chain hash
		IsBuilder:       false,
		MaxBuilderSlots: 20,
	}
	protoManager, err := protocol.NewManager(protoConfig)
	if err != nil {
		log.Fatalf("Failed to create protocol manager: %v", err)
	}

	// Register protocol handlers
	protoManager.Registry.RegisterHandler(protocol.StreamKindBlockRequest, handlers.NewBlockRequestHandler())

	// Create transport with minimal config
	transportConfig := transport.Config{
		PublicKey:     pub,
		PrivateKey:    priv,
		TLSCert:       tlsCert,
		ListenAddr:    *listenAddr,
		CertValidator: cert.NewValidator(),
		Handler:       protoManager, // Protocol manager implements ConnectionHandler
	}

	tr, err := transport.NewTransport(transportConfig)
	if err != nil {
		log.Fatalf("Failed to create transport: %v", err)
	}

	if err := tr.Start(); err != nil {
		log.Fatalf("Failed to start transport: %v", err)
	}
	defer func() {
		if err := tr.Stop(); err != nil {
			fmt.Printf("Failed to stop transport: %v\n", err)
		}
	}()

	log.Printf("Node listening on %s", *listenAddr)

	// If we have an address to connect to, make a request
	if *connectTo != "" {
		log.Printf("Connecting to peer at %s", *connectTo)

		conn, err := tr.Connect(*connectTo)
		if err != nil {
			log.Fatalf("Failed to connect to peer: %v", err)
		}

		// Create a dummy block hash for the request
		hash := [32]byte{1, 2, 3, 4} // Example hash

		// Create peer with protocol connection
		p := peer.NewPeer(conn, conn.PeerKey(), protoManager)
		ctx := context.Background()
		blocks, err := p.RequestBlocks(ctx, hash, true)
		if err != nil {
			log.Fatalf("Failed to request blocks: %v", err)
		}
		fmt.Printf("blocks: %v\n", blocks)
		log.Printf("Block request completed")
	}

	// Keep the node running
	select {}
}
