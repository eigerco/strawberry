package conformance_testing

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"

	"github.com/eigerco/strawberry/pkg/network/handlers"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/state/merkle"
	"github.com/eigerco/strawberry/internal/state/serialization"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/eigerco/strawberry/internal/store"
)

// Node is a conformance testing node complying with fuzzer protocol https://github.com/davxy/jam-stuff/tree/main/fuzz-proto
// opens a connection via a unix socket and listens to fuzzer messages and updates the state accordingly
type Node struct {
	socketPath string

	mu sync.Mutex

	state    *state.State
	chain    *store.Chain
	trie     *store.Trie
	listener net.Listener

	headerToStateRoot map[crypto.Hash]crypto.Hash
	handshakeDone     bool

	// app info
	appName    []byte
	appVersion Version
	jamVersion Version
}

// NewNode create a new conformance testing node
func NewNode(socketPath string, chain *store.Chain, trie *store.Trie, appName []byte, appVersion, jamVersion Version) *Node {
	return &Node{
		socketPath:        socketPath,
		mu:                sync.Mutex{},
		chain:             chain,
		trie:              trie,
		appName:           appName,
		appVersion:        appVersion,
		jamVersion:        jamVersion,
		headerToStateRoot: make(map[crypto.Hash]crypto.Hash),
	}
}

// Start starts the node server
func (n *Node) Start() error {
	if _, err := os.Stat(n.socketPath); err == nil {
		os.Remove(n.socketPath)
	}

	// Listen on the Unix socket
	listener, err := net.Listen("unix", n.socketPath)
	if err != nil {
		return fmt.Errorf("Failed to listen on unix socket: %v\n", err)
	}
	n.listener = listener

	fmt.Printf("Listening on unix socket: %s\n", n.socketPath)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Accept error: %v\n", err)
			continue
		}
		go n.handleConnection(conn)
	}
}

// Stop stops the node server
func (n *Node) Stop() error {
	return n.listener.Close()
}

func (n *Node) handleConnection(conn net.Conn) {
	defer conn.Close()
	for {
		ctx := context.Background()

		msgBytes, err := handlers.ReadMessageWithContext(ctx, conn)
		if err != nil {
			log.Printf("error reading from connection: %v", err)
			return
		}
		msg := &Message{}
		if err := jam.Unmarshal(msgBytes.Content, msg); err != nil {
			log.Printf("error unmarshalling message: %v", err)
			return
		}

		responseMsg, err := n.messageHandler(msg)
		if err != nil {
			log.Printf("error handling message: %v", err)
			return
		}

		respMsgBytes, err := jam.Marshal(responseMsg)
		if err != nil {
			log.Printf("error marshalling response: %v", err)
			return
		}

		if err := handlers.WriteMessageWithContext(ctx, conn, respMsgBytes); err != nil {
			log.Printf("error writing response: %v", err)
			return
		}
	}
}

// messageHandler handling of each message choice type according to the protocol description
func (n *Node) messageHandler(msg *Message) (*Message, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if choice, ok := msg.Get().(PeerInfo); ok {
		log.Println("Client handshake initiated:")
		log.Println("Client app name", string(choice.Name))
		log.Println("Client app version", choice.AppVersion.String())
		log.Println("Client jam version", choice.JamVersion.String())
		n.handshakeDone = true
		return NewMessage(PeerInfo{
			Name:       n.appName,
			AppVersion: n.appVersion,
			JamVersion: n.jamVersion,
		}), nil
	}

	if !n.handshakeDone {
		return nil, errors.New("handshake was not performed, peer info message should be sent first")
	}
	switch choice := msg.Get().(type) {
	case SetState:
		// Initialize state
		newState, err := deserializeState(choice.State.StateItems)
		if err != nil {
			return nil, fmt.Errorf("error deserializing state items: %v", err)
		}

		n.state = &newState
		stateRoot, err := merkle.MerklizeState(newState, n.trie)
		if err != nil {
			return nil, fmt.Errorf("failed to merklize state: %v", err)
		}
		if err := n.chain.PutHeader(choice.Header); err != nil {
			return nil, fmt.Errorf("failed to put header: %v", err)
		}
		headerHash, err := choice.Header.Hash()
		if err != nil {
			return nil, fmt.Errorf("failed to import block: %v", err)
		}
		n.headerToStateRoot[headerHash] = stateRoot

		return NewMessage(StateRoot{
			StateRootHash: stateRoot,
		}), nil
	case ImportBlock:
		if n.state == nil {
			return nil, fmt.Errorf("state not imported")
		}
		err := statetransition.UpdateState(n.state, choice.Block, n.chain, n.trie)
		if err != nil {
			return nil, fmt.Errorf("failed to import block: %v", err)
		}
		stateRoot, err := merkle.MerklizeState(*n.state, n.trie)
		if err != nil {
			return nil, fmt.Errorf("failed to import block: %v", err)
		}

		if err := n.chain.PutBlock(choice.Block); err != nil {
			return nil, fmt.Errorf("failed to import block: %v", err)
		}

		headerHash, err := choice.Block.Header.Hash()
		if err != nil {
			return nil, fmt.Errorf("failed to import block: %v", err)
		}

		n.headerToStateRoot[headerHash] = stateRoot

		return NewMessage(StateRoot{
			StateRootHash: stateRoot,
		}), nil

	case GetState:
		stateRoot, ok := n.headerToStateRoot[choice.HeaderHash]
		if !ok {
			return nil, fmt.Errorf("header hash not found")
		}

		keyValuePairs, err := n.trie.GetFullState(stateRoot)
		if err != nil {
			return nil, fmt.Errorf("failed to get state: %v", err)
		}

		var stateKeyValues []KeyValue
		for _, kvPair := range keyValuePairs {
			stateKeyValues = append(stateKeyValues, KeyValue{
				Key:   kvPair.Key,
				Value: kvPair.Value,
			})
		}

		return NewMessage(State{
			StateItems: stateKeyValues,
		}), nil
	}

	return nil, fmt.Errorf("unknown message type")
}

func deserializeState(keyValues []KeyValue) (s state.State, err error) {
	stateItemsMap := make(map[statekey.StateKey][]byte)
	for _, kv := range keyValues {
		stateItemsMap[kv.Key] = kv.Value
	}

	return serialization.DeserializeState(stateItemsMap)
}
