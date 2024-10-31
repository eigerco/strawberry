package state

import "github.com/eigerco/strawberry/internal/block"

type Memo [TransferMemoSizeBytes]byte

// DeferredTransfer Equation 161: T ≡ (s ∈ Ns, d ∈ Ns, a ∈ Nb, m ∈ Ym, g ∈ Ng)
type DeferredTransfer struct {
	SenderServiceIndex   block.ServiceId // sender service index (s)
	ReceiverServiceIndex block.ServiceId // receiver service index (d)
	Balance              uint64          // balance value (a)
	Memo                 Memo            // memo (m)
	GasLimit             uint64          // gas limit (g)
}
