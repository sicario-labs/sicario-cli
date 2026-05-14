// SAFE: rust-sqlx-format-query — sqlx::query! macro with parameterized binding
// Rule: rust-sqlx-format-query | CWE-89 | Expected: TrueNegative

use sqlx::PgPool;

async fn get_user(pool: &PgPool, user_id: i64) -> Result<String, sqlx::Error> {
    // SAFE: sqlx::query! macro uses compile-time checked parameterized binding;
    // user input is never interpolated into the SQL string via format!
    let row = sqlx::query!(
        "SELECT username FROM users WHERE id = $1",
        user_id
    )
    .fetch_one(pool)
    .await?;

    Ok(row.username)
}

#[tokio::main]
async fn main() {
    let pool = PgPool::connect("postgres://localhost/app").await.unwrap();
    match get_user(&pool, 1).await {
        Ok(name) => println!("user: {}", name),
        Err(e) => eprintln!("error: {}", e),
    }
}
