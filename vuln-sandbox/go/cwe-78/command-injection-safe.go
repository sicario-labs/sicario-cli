// SAFE: go-exec-command-bash-c — allowlist validation prevents command injection
// Rule: go-exec-command-bash-c | CWE-78 | Expected: TrueNegative

package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

var allowedCommands = map[string]bool{
	"date":   true,
	"uptime": true,
	"pwd":    true,
}

func runHandler(w http.ResponseWriter, r *http.Request) {
	command := r.URL.Query().Get("cmd")

	// SAFE: command validated against an allowlist; exec.Command called with fixed args, no bash -c
	if !allowedCommands[command] {
		http.Error(w, "command not allowed", http.StatusBadRequest)
		return
	}

	cmd := exec.Command(command)
	out, err := cmd.Output()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "%s", out)
}

func main() {
	http.HandleFunc("/run", runHandler)
	http.ListenAndServe(":8080", nil)
}
