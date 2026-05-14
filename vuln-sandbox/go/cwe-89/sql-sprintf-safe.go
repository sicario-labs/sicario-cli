// SAFE: go-fmt-sprintf-sql — parameterized query used instead of fmt.Sprintf for SQL
// Rule: go-fmt-sprintf-sql | CWE-89 | Expected: TrueNegative

package main

import (
	"database/sql"
	"fmt"
	"net/http"

	_ "github.com/lib/pq"
)

var db2 *sql.DB

func searchHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")

	// SAFE: parameterized placeholder used; fmt.Sprintf not used to build the query
	rows, err := db2.Query("SELECT * FROM users WHERE name = $1", name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	fmt.Fprintf(w, "search executed safely")
}

func main() {
	var err error
	db2, err = sql.Open("postgres", "postgres://localhost/app?sslmode=disable")
	if err != nil {
		panic(err)
	}
	http.HandleFunc("/search", searchHandler)
	http.ListenAndServe(":8080", nil)
}
