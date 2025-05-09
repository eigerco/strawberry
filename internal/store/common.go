package store

const (
	ErrFailedBatchCommit = "failed to commit batch: %v"
)

// Prefix constants for all store types
const (
	prefixHeader byte = iota + 1
	prefixBlock
	prefixWorkReport
	prefixTrieNode
	prefixTrieNodeValue
	prefixTrieNodeRefCount
	prefixAvailabilityAuditShard
	prefixAvailabilitySegmentsShard
	prefixAvailabilityJustification
)

// PrefixToString converts a prefix byte to a string
func PrefixToString(p byte) string {
	switch p {
	case prefixHeader:
		return "header"
	case prefixBlock:
		return "block"
	case prefixWorkReport:
		return "workReport"
	case prefixTrieNode:
		return "trieNode"
	case prefixTrieNodeValue:
		return "trieNodeValue"
	case prefixTrieNodeRefCount:
		return "trieNodeRefCount"
	default:
		return "unknown"
	}
}

// makeKey creates a key from a prefix and hash
func makeKey(prefix byte, hash []byte) []byte {
	key := make([]byte, 1+len(hash))
	key[0] = prefix
	copy(key[1:], hash)
	return key
}
