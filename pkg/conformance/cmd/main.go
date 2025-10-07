package main

import (
	"flag"
	"log"

	"github.com/eigerco/strawberry/internal/store"
	"github.com/eigerco/strawberry/pkg/conformance"
	"github.com/eigerco/strawberry/pkg/db/pebble"
)

func main() {
	socketPath := flag.String("socket", "/tmp/jam_target.sock", "Path to the socket for the fuzzer to connect to")
	flag.Parse()

	// Ensure no extra positional arguments
	if flag.NArg() > 0 {
		log.Fatalf("unexpected arguments: %v", flag.Args())
	}

	db, err := pebble.NewKVStore()
	if err != nil {
		log.Fatalf("failed to create kv store: %v", err)
	}

	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("error closing database: %v", err)
		}
	}()

	chain := store.NewChain(db)
	trieStore := store.NewTrie(chain)

	appName := []byte("strawberry")
	appVersion := conformance.Version{Major: 0, Minor: 0, Patch: 1}
	jamVersion := conformance.Version{Major: 0, Minor: 7, Patch: 0}
	features := conformance.FeatureFork
	node := conformance.NewNode(*socketPath, chain, trieStore, appName, appVersion, jamVersion, features)
	if err := node.Start(); err != nil {
		log.Fatalf("Failed to start Node: %v", err)
	}
}
