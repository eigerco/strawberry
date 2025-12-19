package conformance

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"

	"github.com/eigerco/strawberry/pkg/network/handlers"
	"github.com/eigerco/strawberry/pkg/serialization/codec/jam"

	"github.com/eigerco/strawberry/internal/crypto"
	"github.com/eigerco/strawberry/internal/guaranteeing"
	"github.com/eigerco/strawberry/internal/state"
	"github.com/eigerco/strawberry/internal/state/merkle"
	"github.com/eigerco/strawberry/internal/state/serialization"
	"github.com/eigerco/strawberry/internal/state/serialization/statekey"
	"github.com/eigerco/strawberry/internal/statetransition"
	"github.com/eigerco/strawberry/internal/store"
)

type Features uint32

const (
	FeatureNone            Features = 0
	FeatureAncestry        Features = 1
	FeatureFork            Features = 2
	FeatureAncestryAndFork Features = 3
	FeatureReserved        Features = 2147483648
)

// Node is a conformance testing node complying with fuzzer protocol https://github.com/davxy/jam-stuff/tree/main/fuzz-proto
// opens a connection via a unix socket and listens to fuzzer messages and updates the state accordingly
type Node struct {
	socketPath string
	mu         sync.Mutex
	chain      *store.Chain
	trie       *store.Trie
	listener   net.Listener

	headerToState map[crypto.Hash]state.State
	handshakeDone bool
	PeerInfo      PeerInfo
}

// NewNode create a new conformance testing node
func NewNode(socketPath string, chain *store.Chain, trie *store.Trie, appName []byte, appVersion, jamVersion Version, features Features) *Node {
	// Enable ancestry validation if the feature flag is set
	if features == FeatureAncestry || features == FeatureAncestryAndFork {
		guaranteeing.Ancestry = true
	}
	peerInfo := PeerInfo{
		FuzzVersion:  1,
		FuzzFeatures: features,
		JamVersion:   jamVersion,
		AppVersion:   appVersion,
		Name:         appName,
	}
	return &Node{
		socketPath:    socketPath,
		mu:            sync.Mutex{},
		chain:         chain,
		trie:          trie,
		PeerInfo:      peerInfo,
		headerToState: make(map[crypto.Hash]state.State),
	}
}

// Start starts the node server
func (n *Node) Start() error {
	// If the socket file exists, try to remove it.
	if _, err := os.Stat(n.socketPath); err == nil {
		if err := os.Remove(n.socketPath); err != nil {
			return fmt.Errorf("failed to remove existing socket file: %v", err)
		}
	}

	// Listen on the Unix socket
	listener, err := net.Listen("unix", n.socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on unix socket: %v", err)
	}
	n.listener = listener

	fmt.Printf("Listening on unix socket: %s\n", n.socketPath)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go n.handleConnection(conn)
	}
}

// Stop stops the node server
func (n *Node) Stop() error {
	return n.listener.Close()
}

func (n *Node) handleConnection(conn net.Conn) {
	defer func() {
		if err := conn.Close(); err != nil {
			log.Printf("error closing connection: %v", err)
		}
	}()
	for {
		ctx := context.Background()

		msgBytes, err := handlers.ReadMessageWithContext(ctx, conn)
		if err != nil {
			if errors.Is(err, io.EOF) {
				log.Println("Fuzzer closed the connection. Session ended.")
			} else {
				log.Printf("Error reading from connection: %v", err)
			}
			return
		}
		msg := &Message{}
		if err := jam.Unmarshal(msgBytes.Content, msg); err != nil {
			log.Printf("error unmarshalling message: %v", err)
			return
		}

		responseMsg, err := n.messageHandler(msg)
		if err != nil {
			responseMsg = NewMessage(Error{Message: []byte(fmt.Sprintf("Chain error: %s", err.Error()))})
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

	if _, ok := msg.Get().(PeerInfo); ok {
		n.handshakeDone = true
		return NewMessage(n.PeerInfo), nil
	}

	if !n.handshakeDone {
		return nil, errors.New("handshake was not performed, peer info message should be sent first")
	}
	switch choice := msg.Get().(type) {
	case Initialize:
		// Initialize state
		state, err := deserializeState(choice.State.StateItems)
		if err != nil {
			return nil, fmt.Errorf("error deserializing state items: %v", err)
		}
		headerHash, err := choice.Header.Hash()
		if err != nil {
			return nil, fmt.Errorf("failed to import block: %v", err)
		}

		if n.PeerInfo.FuzzFeatures == FeatureAncestry || n.PeerInfo.FuzzFeatures == FeatureAncestryAndFork {
			ancestry := choice.Ancestry
			for _, item := range ancestry.Items {
				err := n.chain.PutConformanceHeader(item.Hash, item.Slot)
				if err != nil {
					return nil, fmt.Errorf("failed to put ancestry header: %v", err)
				}
			}
		}
		stateRoot, err := merkle.MerklizeStateOnly(state)
		if err != nil {
			return nil, fmt.Errorf("failed to merklize state: %v", err)
		}
		if err := n.chain.PutHeader(choice.Header); err != nil {
			return nil, fmt.Errorf("failed to put header: %v", err)
		}
		n.headerToState[headerHash] = state

		return NewMessage(StateRoot{
			StateRootHash: stateRoot,
		}), nil

	case ImportBlock:
		if len(n.headerToState) == 0 {
			return nil, fmt.Errorf("state not imported")
		}
		state, ok := n.headerToState[choice.Block.Header.ParentHash]
		if !ok {
			return nil, fmt.Errorf("parent state not found")
		}
		err := statetransition.UpdateState(&state, choice.Block, n.chain, n.trie)
		if err != nil {
			return nil, fmt.Errorf("failed to import block: %v", err)
		}
		headerHash, err := choice.Block.Header.Hash()
		if err != nil {
			return nil, fmt.Errorf("failed to import block: %v", err)
		}
		stateRoot, err := merkle.MerklizeStateOnly(state)
		if err != nil {
			return nil, fmt.Errorf("failed to import block: %v", err)
		}
		if err := n.chain.PutBlock(choice.Block); err != nil {
			return nil, fmt.Errorf("failed to import block: %v", err)
		}

		n.headerToState[headerHash] = state

		return NewMessage(StateRoot{
			StateRootHash: stateRoot,
		}), nil

	case GetState:
		state, ok := n.headerToState[choice.HeaderHash]
		if !ok {
			return nil, fmt.Errorf("header hash not found")
		}

		keyValuePairs, err := serializeState(state)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize state: %v", err)
		}

		return NewMessage(State{
			StateItems: keyValuePairs,
		}), nil
	}

	return nil, fmt.Errorf("unknown message type")
}

func serializeState(s state.State) (keyValues []statekey.KeyValue, err error) {
	stateItemsMap, err := serialization.SerializeState(s)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize state: %v", err)
	}

	keyValues = make([]statekey.KeyValue, 0, len(stateItemsMap))
	for key, value := range stateItemsMap {
		keyValues = append(keyValues, statekey.KeyValue{
			Key:   key,
			Value: value,
		})
	}
	return keyValues, nil
}

func deserializeState(keyValues []statekey.KeyValue) (s state.State, err error) {
	stateItemsMap := make(map[statekey.StateKey][]byte)
	for _, kv := range keyValues {
		stateItemsMap[kv.Key] = kv.Value
	}

	return serialization.DeserializeState(stateItemsMap)
}
