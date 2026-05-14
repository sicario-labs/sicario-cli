// SAFE: rust-diesel-sql-query-format — Diesel ORM query builder used instead of raw SQL
// Rule: rust-diesel-sql-query-format | CWE-89 | Expected: TrueNegative

use diesel::prelude::*;
use diesel::pg::PgConnection;

table! {
    users (id) {
        id -> Int8,
        username -> Varchar,
    }
}

fn get_user(conn: &mut PgConnection, user_id: i64) -> QueryResult<String> {
    // SAFE: Diesel's query builder generates parameterized SQL; no raw string interpolation
    users::table
        .filter(users::id.eq(user_id))
        .select(users::username)
        .first::<String>(conn)
}

fn main() {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let mut conn = PgConnection::establish(&database_url).unwrap();
    match get_user(&mut conn, 1) {
        Ok(name) => println!("user: {}", name),
        Err(e) => eprintln!("error: {}", e),
    }
}
