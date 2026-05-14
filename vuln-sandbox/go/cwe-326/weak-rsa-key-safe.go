// SAFE: go-weak-rsa-key-size — RSA key generated with 4096-bit modulus
// Rule: go-weak-rsa-key-size | CWE-326 | Expected: TrueNegative

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

func main() {
	// SAFE: 4096-bit RSA key exceeds the minimum recommended 2048-bit key size
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Println("Error generating key:", err)
		return
	}

	publicKey := &privateKey.PublicKey
	message := []byte("Hello, secure world!")

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, message, nil)
	if err != nil {
		fmt.Println("Error encrypting:", err)
		return
	}

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
	if err != nil {
		fmt.Println("Error decrypting:", err)
		return
	}

	fmt.Println("Decrypted:", string(plaintext))
}
