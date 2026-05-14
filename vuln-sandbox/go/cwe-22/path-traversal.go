// VULNERABLE: go-os-open-concat — os.Open with string concatenation path
// Rule: go-os-open-concat | CWE-22 | Severity: HIGH

package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

func fileHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")

	// VULNERABLE: user-controlled filename concatenated into file path
	// An attacker can pass: ../../etc/passwd to read arbitrary files
	f, err := os.Open("/uploads/" + filename)
	if err != nil {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "%s", data)
}

func main() {
	http.HandleFunc("/file", fileHandler)
	http.ListenAndServe(":8080", nil)
}
