package reedsolomon

import (
	_ "embed"
)

const rustLibraryName = "liberasurecoding.so"

//go:embed lib/liberasurecoding.so
var rustLibraryBytes []byte
