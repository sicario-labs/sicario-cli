// VULNERABLE: rust-diesel-sql-query-format — diesel::sql_query with format! string
// Rule: rust-diesel-sql-query-format | CWE-89 | Severity: HIGH

use diesel::prelude::*;
use diesel::sql_query;

#[derive(QueryableByName)]
struct User {
    #[diesel(sql_type = diesel::sql_types::Text)]
    username: String,
}

fn search_users(conn: &mut PgConnection, name: &str) -> Vec<User> {
    // VULNERABLE: user-controlled name interpolated into SQL via format!
    // An attacker can pass: ' OR '1'='1 to bypass authentication
    diesel::sql_query(format!("SELECT username FROM users WHERE name = '{}'", name))
        .load::<User>(conn)
        .unwrap_or_default()
}

fn main() {
    let database_url = "postgres://localhost/app";
    let mut conn = PgConnection::establish(database_url).unwrap();
    let users = search_users(&mut conn, "alice");
    for user in users {
        println!("{}", user.username);
    }
}
