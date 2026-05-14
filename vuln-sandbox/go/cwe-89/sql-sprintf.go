// VULNERABLE: go-fmt-sprintf-sql — fmt.Sprintf used to build SQL query
// Rule: go-fmt-sprintf-sql | CWE-89 | Severity: HIGH

package main

import (
	"database/sql"
	"fmt"
	"net/http"

	_ "github.com/lib/pq"
)

var db *sql.DB

func searchHandler(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")

	// VULNERABLE: fmt.Sprintf interpolates user input directly into SQL
	// An attacker can pass: ' OR '1'='1 to bypass authentication
	query := fmt.Sprintf("SELECT * FROM users WHERE email = '%s'", email)
	row := db.QueryRow(query)

	var id int
	var name string
	if err := row.Scan(&id, &name); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	fmt.Fprintf(w, "user: %s", name)
}

func main() {
	var err error
	db, err = sql.Open("postgres", "postgres://localhost/app?sslmode=disable")
	if err != nil {
		panic(err)
	}
	http.HandleFunc("/search", searchHandler)
	http.ListenAndServe(":8080", nil)
}
