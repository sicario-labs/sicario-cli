// VULNERABLE: go-http-get-sprintf — http.Get with fmt.Sprintf URL from user input
// Rule: go-http-get-sprintf | CWE-918 | Severity: HIGH

package main

import (
	"fmt"
	"io"
	"net/http"
)

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	userHost := r.URL.Query().Get("host")

	// VULNERABLE: user-controlled host used to construct outbound HTTP request
	// An attacker can pass: 169.254.169.254/latest/meta-data to access cloud metadata
	resp, err := http.Get(fmt.Sprintf("http://%s/api/data", userHost))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Fprintf(w, "%s", body)
}

func main() {
	http.HandleFunc("/proxy", proxyHandler)
	http.ListenAndServe(":8080", nil)
}
