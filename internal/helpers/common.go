package helpers

import (
	"fmt"
	"strings"
)

type Field struct {
	Values map[string]string
}

func (f *Field) SetValue(key, value string) {
	f.Values[key] = value
}

func BytesToHexArray(shellCode []byte) string {
	var stringsArray []string
	for i, b := range shellCode {
		if i+1 == len(shellCode) {
			stringsArray = append(stringsArray, fmt.Sprintf("0x%02x", b))

		} else {
			stringsArray = append(stringsArray, fmt.Sprintf("0x%02x", b)+", ")
		}
	}
	result := strings.Join(stringsArray, "")
	return result
}
