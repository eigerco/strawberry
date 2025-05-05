package peer

// MergeValidators returns a deduplicated set of validator peers from slices a and b,
// including only peers that are validators (ValidatorIndex != nil)
// Deduplication is performed based on Ed25519 public keys
func MergeValidators(a, b []*Peer) []*Peer {
	exists := make(map[string]struct{})
	var merged []*Peer

	// Include only valid peers from `a`
	for _, p := range a {
		if p.ValidatorIndex == nil {
			continue
		}
		key := string(p.Ed25519Key)
		if _, seen := exists[key]; !seen {
			exists[key] = struct{}{}
			merged = append(merged, p)
		}
	}

	// Include only valid, non-duplicate peers from `b`
	for _, p := range b {
		if p.ValidatorIndex == nil {
			continue
		}
		key := string(p.Ed25519Key)
		if _, seen := exists[key]; !seen {
			exists[key] = struct{}{}
			merged = append(merged, p)
		}
	}

	return merged
}
