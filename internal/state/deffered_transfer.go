package state

// DeferredTransfer Equation 161: T ≡ (s ∈ Ns, d ∈ Ns, a ∈ Nb, m ∈ Ym, g ∈ Ng)
type DeferredTransfer struct {
	SenderServiceIndex   uint32    // sender service index (s)
	ReceiverServiceIndex uint32    // receiver service index (d)
	Balance              uint64    // balance value (a)
	Memo                 [128]byte // memo (m)
	GasLimit             uint32    // gas limit (g)
}
