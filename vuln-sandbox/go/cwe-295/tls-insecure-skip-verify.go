// VULNERABLE: go/tls-insecure-skip-verify — InsecureSkipVerify: true disables TLS cert validation
// Rule: go/tls-insecure-skip-verify | CWE-295 | Severity: CRITICAL

package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
)

func fetchData(url string) (string, error) {
	// VULNERABLE: InsecureSkipVerify disables TLS certificate validation
	// This allows man-in-the-middle attacks against all HTTPS connections
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get(url)
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
	data, err := fetchData("https://api.example.com/data")
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
	fmt.Println(data)
}
