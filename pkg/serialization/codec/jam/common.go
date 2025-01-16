package jam

import (
	"fmt"
	"strings"
)

func IntLength(in any) (uint, error) {
	switch in.(type) {
	case uint8, int8:
		return 1, nil
	case uint16, int16:
		return 2, nil
	case uint32, int32:
		return 4, nil
	case uint64, int64:
		return 8, nil
	default:
		return 0, fmt.Errorf(ErrUnsupportedType, in)
	}
}

func parseTag(tag string) map[string]string {
	result := make(map[string]string)
	pairs := strings.Split(tag, ",")
	for _, pair := range pairs {
		kv := strings.Split(pair, "=")
		if len(kv) == 2 {
			result[kv[0]] = kv[1]
		}
	}
	return result
}
