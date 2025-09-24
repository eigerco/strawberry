package bandersnatch

import (
	_ "embed"
)

const rustLibraryName = "libbandersnatch.dylib"

//go:embed lib/libbandersnatch.dylib
var rustLibraryBytes []byte
