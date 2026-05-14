// SAFE: go-sql-string-concat — parameterized query prevents SQL injection
// Rule: go-sql-string-concat | CWE-89 | Expected: TrueNegative

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

	// SAFE: user input passed as a parameterized query argument, never concatenated
	rows, err := db.Query("SELECT * FROM users WHERE id = $1", userId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	fmt.Fprintf(w, "query executed safely")
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
