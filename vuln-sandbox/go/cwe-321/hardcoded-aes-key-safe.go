// SAFE: go-hardcoded-aes-key — AES key loaded from environment variable
// Rule: go-hardcoded-aes-key | CWE-321 | Expected: TrueNegative

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

func encrypt(plaintext []byte) ([]byte, error) {
	// SAFE: key loaded from environment variable; never hardcoded in source
	keyHex := os.Getenv("AES_KEY")
	if keyHex == "" {
		return nil, fmt.Errorf("AES_KEY environment variable must be set")
	}

	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("AES_KEY must be 32 bytes (64 hex chars)")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func main() {
	ciphertext, err := encrypt([]byte("sensitive data"))
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("Encrypted %d bytes\n", len(ciphertext))
}
