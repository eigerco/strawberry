package crypto

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type Hash [HashSize]byte

func (h Hash) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("0x%s", hex.EncodeToString(h[:])))
}
