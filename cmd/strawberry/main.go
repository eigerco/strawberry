package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/eigerco/strawberry/pkg/network/peer"
)

// main starts a blockchain node.
// go run main.go -addr localhost:9000
func main() {
	ctx := context.Background()
	listenAddr := flag.String("addr", "", "Listen address")
	flag.Parse()

	if *listenAddr == "" {
		log.Fatal("listen address is required")
	}
	// Generate node keys
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatalf("Failed to generate keys: %v", err)
	}
	keys := peer.ValidatorKeys{
		EdPrv: priv,
		EdPub: pub,
	}

	address, err := net.ResolveUDPAddr("", *listenAddr)
	if err != nil {
		fmt.Printf("err: %v\n", err)
	}
	fmt.Printf("listening on: %v\n", address)
	node, err := peer.NewNode(ctx, address, keys)
	if err != nil {
		log.Fatalf("Failed to create node: %v", err)
	}
	err = node.Start()
	if err != nil {
		fmt.Printf("err: %v\n", err)
	}

	select {}
}
