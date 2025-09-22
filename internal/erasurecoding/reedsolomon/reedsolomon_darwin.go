package reedsolomon

import (
	_ "embed"
)

const rustLibraryName = "liberasurecoding.dylib"

//go:embed lib/liberasurecoding.dylib
var rustLibraryBytes []byte
