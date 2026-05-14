// SAFE: go-os-open-concat — path.Clean and containment check prevent directory traversal
// Rule: go-os-open-concat | CWE-22 | Expected: TrueNegative

package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const uploadDir = "/uploads"

func fileHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")

	// SAFE: clean the path and verify it stays within the allowed directory
	cleanPath := filepath.Clean(filepath.Join(uploadDir, filename))
	if !strings.HasPrefix(cleanPath, uploadDir+string(os.PathSeparator)) {
		http.Error(w, "invalid file path", http.StatusBadRequest)
		return
	}

	f, err := os.Open(cleanPath)
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
