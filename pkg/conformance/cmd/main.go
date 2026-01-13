package main

import (
	"flag"
	"log"

	"github.com/eigerco/strawberry/pkg/conformance"
)

func main() {
	socketPath := flag.String("socket", "/tmp/jam_target.sock", "Path to the socket for the fuzzer to connect to")
	flag.Parse()

	// Ensure no extra positional arguments
	if flag.NArg() > 0 {
		log.Fatalf("unexpected arguments: %v", flag.Args())
	}

	appName := []byte("strawberry")
	appVersion := conformance.Version{Major: 0, Minor: 0, Patch: 2}
	jamVersion := conformance.Version{Major: 0, Minor: 7, Patch: 2}
	features := conformance.FeatureAncestryAndFork
	node := conformance.NewNode(*socketPath, appName, appVersion, jamVersion, features)
	if err := node.Start(); err != nil {
		log.Fatalf("Failed to start Node: %v", err)
	}
}
