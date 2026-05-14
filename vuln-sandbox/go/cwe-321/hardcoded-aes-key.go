// VULNERABLE: go-hardcoded-aes-key — AES cipher initialized with hardcoded key literal
// Rule: go-hardcoded-aes-key | CWE-321 | Severity: CRITICAL

package main

import (
	"crypto/aes"
	"fmt"
)

func getEncryptionBlock() {
	// VULNERABLE: AES key is hardcoded as a byte literal in source code
	// Anyone with access to the binary or source can extract the key
	block, err := aes.NewCipher([]byte("my-secret-key-16"))
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
	fmt.Printf("block size: %d\n", block.BlockSize())
}

func main() {
	getEncryptionBlock()
}
