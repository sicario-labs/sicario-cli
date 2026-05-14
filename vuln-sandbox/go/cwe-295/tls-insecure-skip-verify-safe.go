// SAFE: go/tls-insecure-skip-verify — TLS certificate verification enabled (default)
// Rule: go/tls-insecure-skip-verify | CWE-295 | Expected: TrueNegative

package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
)

func fetchSecureData(targetURL string) (string, error) {
	// SAFE: InsecureSkipVerify is false (default); certificate verification is enabled
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
	}

	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	resp, err := client.Get(targetURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func main() {
	data, err := fetchSecureData("https://api.example.com/data")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println(data)
}
