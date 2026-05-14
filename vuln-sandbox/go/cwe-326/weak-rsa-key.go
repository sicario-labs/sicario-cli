// VULNERABLE: go-weak-rsa-key-size — RSA key size below 2048 bits
// Rule: go-weak-rsa-key-size | CWE-326 | Severity: HIGH

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

func generateKey() (*rsa.PrivateKey, error) {
	// VULNERABLE: 1024-bit RSA key is considered insecure
	// NIST recommends at least 2048 bits; 4096 bits preferred for long-term security
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func main() {
	key, err := generateKey()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
	fmt.Printf("key size: %d bits\n", key.N.BitLen())
}
