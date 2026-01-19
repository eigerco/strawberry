package main

import (
	"flag"
	"log"
	"net/http"
	_ "net/http/pprof"

	"github.com/eigerco/strawberry/pkg/conformance"
)

func main() {
	socketPath := flag.String("socket", "/tmp/jam_target.sock", "Path to the socket for the fuzzer to connect to")
	pprofAddr := flag.String("pprof", "", "Address for pprof HTTP server (e.g., localhost:6060)")
	flag.Parse()

	// Ensure no extra positional arguments
	if flag.NArg() > 0 {
		log.Fatalf("unexpected arguments: %v", flag.Args())
	}

	// Start pprof server if address provided
	if *pprofAddr != "" {
		go func() {
			log.Printf("Starting pprof server on %s", *pprofAddr)
			if err := http.ListenAndServe(*pprofAddr, nil); err != nil {
				log.Printf("pprof server error: %v", err)
			}
		}()
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
