package traceutil

import (
	"github.com/eigerco/strawberry/internal/block"
	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
	"github.com/eigerco/strawberry/pkg/conformance"
	"github.com/eigerco/strawberry/tests/integration"
)

func CreatePeerInfoMessage() *conformance.Message {
	return conformance.NewMessage(conformance.PeerInfo{
		FuzzVersion:  1,
		FuzzFeatures: conformance.FeatureFork,
		JamVersion: conformance.Version{
			Major: 0,
			Minor: 7,
			Patch: 1,
		},
		AppVersion: conformance.Version{
			Major: 1,
			Minor: 0,
			Patch: 0,
		},
		Name: []byte("test-node"),
	})
}

func GenesisToConformanceInitialize(genesis integration.Genesis) conformance.Initialize {
	return conformance.Initialize{
		Header: genesis.Header,
		State:  traceStateToConformanceState(genesis.State),
		Ancestry: conformance.Ancestry{
			Items: []conformance.AncestryItem{},
		},
	}
}

func TraceToConformanceInitialize(trace integration.Trace) conformance.Initialize {
	return conformance.Initialize{
		Header: block.Header{},
		State:  traceStateToConformanceState(trace.PreState),
		Ancestry: conformance.Ancestry{
			Items: []conformance.AncestryItem{},
		},
	}
}

func TraceToConformanceImportBlock(trace integration.Trace) conformance.ImportBlock {
	return conformance.ImportBlock{
		Block: trace.Block,
	}
}

func TraceToConformancePostState(trace integration.Trace) conformance.State {
	return traceStateToConformanceState(trace.PostState)
}

func CreateGetStateMessage(stateRootHash crypto.Hash) *conformance.Message {
	return conformance.NewMessage(conformance.GetState{
		HeaderHash: stateRootHash,
	})
}

func KeyValueStateToStateMap(kvs []statekey.KeyValue) map[statekey.StateKey][]byte {
	m := make(map[statekey.StateKey][]byte)
	for _, entry := range kvs {
		m[entry.Key] = entry.Value
	}
	return m
}

func traceStateToConformanceState(state integration.StateWithRoot) conformance.State {
	return conformance.State{
		StateItems: state.KeyValues,
	}
}
