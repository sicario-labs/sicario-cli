// SAFE: go-http-get-sprintf — URL validated against allowlist before outbound request
// Rule: go-http-get-sprintf | CWE-918 | Expected: TrueNegative

package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
)

var allowedHosts = map[string]bool{
	"api.example.com":  true,
	"data.example.com": true,
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url")

	// SAFE: parse and validate the URL against an allowlist of trusted hosts
	parsed, err := url.Parse(targetURL)
	if err != nil || !allowedHosts[parsed.Hostname()] {
		http.Error(w, "URL not allowed", http.StatusBadRequest)
		return
	}

	resp, err := http.Get(parsed.String())
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
