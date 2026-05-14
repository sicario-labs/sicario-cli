// VULNERABLE: go-sql-string-concat — SQL query built with string concatenation
// Rule: go-sql-string-concat | CWE-89 | Severity: HIGH

package main

import (
	"database/sql"
	"fmt"
	"net/http"

	_ "github.com/lib/pq"
)

var db *sql.DB

func getUserHandler(w http.ResponseWriter, r *http.Request) {
	userId := r.URL.Query().Get("id")

	// VULNERABLE: user-controlled input concatenated directly into SQL query
	// An attacker can pass: 1 OR 1=1 -- to dump all users
	query := "SELECT * FROM users WHERE id = " + userId
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	fmt.Fprintf(w, "query executed")
}

func main() {
	var err error
	db, err = sql.Open("postgres", "postgres://localhost/app?sslmode=disable")
	if err != nil {
		panic(err)
	}
	http.HandleFunc("/user", getUserHandler)
	http.ListenAndServe(":8080", nil)
}
