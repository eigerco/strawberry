package work

// ZeroPadding Pn(. . . ) The octet-array zero-padding function (14.17 v0.5.2)
func ZeroPadding(x []byte, n uint) []byte {
	if n == 0 {
		return x
	}

	// ((|x|+n-1) mod n)+1...n
	start, end := ((len(x)+int(n)-1)%int(n))+1, int(n)

	paddingLength := end - start
	if paddingLength <= 0 {
		return x
	}

	return append(x, make([]byte, paddingLength)...)
}
