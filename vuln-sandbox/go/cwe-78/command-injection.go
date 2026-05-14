// VULNERABLE: go-exec-command-bash-c — exec.Command with bash -c and user input
// Rule: go-exec-command-bash-c | CWE-78 | Severity: CRITICAL

package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

func runHandler(w http.ResponseWriter, r *http.Request) {
	userCommand := r.URL.Query().Get("cmd")

	// VULNERABLE: user input passed to bash -c allows arbitrary command execution
	// An attacker can pass: ls; cat /etc/passwd to read sensitive files
	cmd := exec.Command("bash", "-c", userCommand)
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
