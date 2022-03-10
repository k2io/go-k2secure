// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_utils

import (
	"strings"
)

// ---------------------------------------------------
// String Utils
// ---------------------------------------------------
func CaseInsensitiveEquals(s, substr string) bool {
	s, substr = strings.ToUpper(s), strings.ToUpper(substr)
	if s == substr {
		return true
	}
	return false
}

func GetSubString(data string, i, j int) string {
	if i < 0 {
		i = 0
	}
	if j >= len(data) {
		j = len(data) - 1
	}
	return data[i:j]

}
func CaseInsensitiveContains(s, substr string) bool {
	s, substr = strings.ToUpper(s), strings.ToUpper(substr)
	return strings.Contains(s, substr)
}

func CheckGrpcByte(a [][]byte, b []byte) bool {
	for x := range a {
		// In Grpc Handling first 5 bytes used to identify length of data stream.
		tmp := a[x]
		if len(tmp) > 5 {
			tmp = tmp[5:]
		}
		if checkbyte(tmp, b) {
			return true
		}

	}
	return false
}

func checkbyte(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
