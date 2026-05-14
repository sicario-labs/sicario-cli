// SAFE: go-des-cipher-usage — AES-256-GCM used instead of weak DES cipher
// Rule: go-des-cipher-usage | CWE-327 | Expected: TrueNegative

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	// SAFE: AES-256-GCM is a strong authenticated encryption algorithm; DES is not used
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
	key := make([]byte, 32) // 256-bit key
	rand.Read(key)

	ciphertext, err := encrypt([]byte("sensitive data"), key)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("Encrypted %d bytes\n", len(ciphertext))
}
