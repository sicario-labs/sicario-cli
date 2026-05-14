// SAFE: go/http-redirect-user-input — redirect target validated against allowlist
// Rule: go/http-redirect-user-input | CWE-601 | Expected: TrueNegative

package main

import (
	"net/http"
)

var allowedPaths = map[string]bool{
	"/dashboard": true,
	"/profile":   true,
	"/settings":  true,
	"/home":      true,
}

func redirectHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("to")

	// SAFE: only redirect to known internal paths; reject external URLs
	if !allowedPaths[target] {
		http.Redirect(w, r, "/home", http.StatusFound)
		return
	}

	http.Redirect(w, r, target, http.StatusFound)
}

func main() {
	http.HandleFunc("/redirect", redirectHandler)
	http.ListenAndServe(":8080", nil)
}
