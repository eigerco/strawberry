package bandersnatch

import (
	_ "embed"
)

const rustLibraryName = "libbandersnatch.so"

//go:embed lib/libbandersnatch.so
var rustLibraryBytes []byte
