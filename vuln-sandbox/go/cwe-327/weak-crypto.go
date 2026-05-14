// VULNERABLE: go-des-cipher-usage — DES cipher is broken (56-bit key)
// Rule: go-des-cipher-usage | CWE-327 | Severity: HIGH

package main

import (
	"crypto/des"
	"fmt"
)

func encryptData(key, plaintext []byte) ([]byte, error) {
	// VULNERABLE: DES is a broken cipher with a 56-bit key
	// It can be brute-forced in hours with modern hardware
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(plaintext))
	block.Encrypt(ciphertext, plaintext)
	return ciphertext, nil
}

func main() {
	key := []byte("8bytekey")
	data := []byte("sensitive")
	encrypted, err := encryptData(key, data)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
	fmt.Printf("encrypted: %x\n", encrypted)
}
