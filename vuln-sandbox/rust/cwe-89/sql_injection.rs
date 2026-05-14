// VULNERABLE: rust-sqlx-format-query — sqlx::query with format! string
// Rule: rust-sqlx-format-query | CWE-89 | Severity: HIGH

use sqlx::PgPool;

async fn get_user(pool: &PgPool, user_id: &str) -> Result<String, sqlx::Error> {
    // VULNERABLE: user-controlled input interpolated into SQL via format!
    // An attacker can pass: 1 OR 1=1 -- to dump all users
    let row = sqlx::query(&format!("SELECT username FROM users WHERE id = {}", user_id))
        .fetch_one(pool)
        .await?;

    Ok(row.get::<String, _>("username"))
}

#[tokio::main]
async fn main() {
    let pool = PgPool::connect("postgres://localhost/app").await.unwrap();
    match get_user(&pool, "1").await {
        Ok(name) => println!("user: {}", name),
        Err(e) => eprintln!("error: {}", e),
    }
}
