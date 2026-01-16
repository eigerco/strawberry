package conformance

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"

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
	"github.com/eigerco/strawberry/pkg/db/pebble"
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
	chain      *store.Chain
	trie       *store.Trie
	listener   net.Listener

	headerToState map[crypto.Hash]stateSnapshot
	mainChainHead *crypto.Hash // current head of the main chain
	headParent    *crypto.Hash // parent of the current head (for mutations)
	handshakeDone bool
	PeerInfo      PeerInfo
}

type stateSnapshot struct {
	state     state.State
	keyVals   []statekey.KeyValue
	stateRoot crypto.Hash
}

// NewNode create a new conformance testing node
func NewNode(socketPath string, appName []byte, appVersion, jamVersion Version, features Features) *Node {
	peerInfo := PeerInfo{
		FuzzVersion:  1,
		FuzzFeatures: features,
		JamVersion:   jamVersion,
		AppVersion:   appVersion,
		Name:         appName,
	}
	return &Node{
		socketPath: socketPath,
		PeerInfo:   peerInfo,
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

	// Reset state for new session
	db, err := pebble.NewKVStore()
	if err != nil {
		log.Printf("error creating db: %v", err)
		return
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("error closing db: %v", err)
		}
	}()
	n.chain = store.NewChain(db)
	n.trie = store.NewTrie(n.chain)
	n.headerToState = make(map[crypto.Hash]stateSnapshot)
	n.mainChainHead = nil
	n.headParent = nil
	n.handshakeDone = false
	guaranteeing.Ancestry = false

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
	if peerInfo, ok := msg.Get().(PeerInfo); ok {
		switch peerInfo.FuzzFeatures {
		case FeatureFork:
			n.PeerInfo.FuzzFeatures = FeatureFork
			guaranteeing.Ancestry = false
		case FeatureAncestryAndFork:
			n.PeerInfo.FuzzFeatures = FeatureAncestryAndFork
			guaranteeing.Ancestry = true
		default:
			return nil, errors.New("forks feature is mandatory but not supported by peer")
		}
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
		stateRoot, err := merkle.MerklizeStateOnly(choice.State.StateItems)
		if err != nil {
			return nil, fmt.Errorf("failed to merklize state: %v", err)
		}
		if n.PeerInfo.FuzzFeatures == FeatureAncestry || n.PeerInfo.FuzzFeatures == FeatureAncestryAndFork {
			if err := n.chain.PutHeader(choice.Header); err != nil {
				return nil, fmt.Errorf("failed to put header: %v", err)
			}
		}
		n.headerToState[headerHash] = stateSnapshot{
			state:     state,
			keyVals:   choice.State.StateItems,
			stateRoot: stateRoot,
		}
		n.mainChainHead = &headerHash
		n.headParent = nil

		return NewMessage(StateRoot{
			StateRootHash: stateRoot,
		}), nil

	case ImportBlock:
		if len(n.headerToState) == 0 {
			return nil, fmt.Errorf("state not imported")
		}
		parentHash := choice.Block.Header.ParentHash
		snapshot, ok := n.headerToState[parentHash]
		if !ok {
			return nil, fmt.Errorf("parent state not found")
		}

		// Validate fork depth before expensive operations
		isExtendingMainChain := n.mainChainHead != nil && parentHash == *n.mainChainHead
		isMutation := n.headParent != nil && parentHash == *n.headParent
		if !isExtendingMainChain && !isMutation {
			return nil, fmt.Errorf("invalid fork depth: can only build on head or head's parent")
		}

		state := snapshot.state
		err := statetransition.UpdateStateWithPriorRoot(&state, snapshot.stateRoot, choice.Block, n.chain)
		if err != nil {
			return nil, fmt.Errorf("failed to import block: %v", err)
		}
		headerHash, err := choice.Block.Header.Hash()
		if err != nil {
			return nil, fmt.Errorf("failed to import block: %v", err)
		}

		// Serialize the new state to get key-values for storage
		newStateKeyVals, err := serializeState(state)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize state: %v", err)
		}

		stateRoot, err := merkle.MerklizeStateOnly(newStateKeyVals)
		if err != nil {
			return nil, fmt.Errorf("failed to import block: %v", err)
		}
		if n.PeerInfo.FuzzFeatures == FeatureAncestry || n.PeerInfo.FuzzFeatures == FeatureAncestryAndFork {
			if err := n.chain.PutBlock(choice.Block); err != nil {
				return nil, fmt.Errorf("failed to import block: %v", err)
			}
		}

		// Store the new state
		n.headerToState[headerHash] = stateSnapshot{
			state:     state,
			keyVals:   newStateKeyVals,
			stateRoot: stateRoot,
		}

		// If extending main chain, prune old states and update pointers
		if isExtendingMainChain {
			if n.headParent != nil {
				// Delete all states except current head (becomes new parent) and new block
				for hash := range n.headerToState {
					if hash != *n.mainChainHead && hash != headerHash {
						delete(n.headerToState, hash)
					}
				}
			}
			n.headParent = n.mainChainHead
			n.mainChainHead = &headerHash
		}
		// If mutation, no changes needed - state is stored, no limit enforced

		return NewMessage(StateRoot{
			StateRootHash: stateRoot,
		}), nil

	case GetState:
		snapshot, ok := n.headerToState[choice.HeaderHash]
		if !ok {
			return nil, fmt.Errorf("header hash not found")
		}

		return NewMessage(State{
			StateItems: snapshot.keyVals,
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
