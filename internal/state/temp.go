package state

import (
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/time"
)

// TODO: They are here for now just to have something to work with until we have the full block ready. The underlying types are made up.

type Extrinsics struct {
	Tickets      Tickets      // ET
	Judgements   Judgements   // EV
	Preimages    Preimages    // EP
	Availability Availability // EA
	Reports      Reports      // EG
}
type Tickets map[crypto.Hash]int
type Preimages map[crypto.Hash][]byte
type Availability map[int]bool
type Reports []string

type Block struct {
	Header     Header     // H
	Extrinsics Extrinsics // E
	// ...
}
type Header struct {
	TimeslotIndex time.Timeslot
	// ...
}
