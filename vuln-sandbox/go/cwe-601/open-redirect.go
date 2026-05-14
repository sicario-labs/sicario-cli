// VULNERABLE: go/http-redirect-user-input — HTTP redirect with user-controlled URL
// Rule: go/http-redirect-user-input | CWE-601 | Severity: MEDIUM

package main

import (
	"net/http"
)

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: redirect target is taken directly from user-supplied query parameter
	// An attacker can craft: /login?next=https://evil.com to redirect victims
	next := r.URL.Query().Get("next")
	http.Redirect(w, r, next, http.StatusFound)
}

func main() {
	http.HandleFunc("/login", loginHandler)
	http.ListenAndServe(":8080", nil)
}
