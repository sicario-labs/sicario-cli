// SAFE: rust-sql-string-concat — database credentials loaded from environment variables
// Rule: rust-sql-string-concat | CWE-798 | Expected: TrueNegative

use sqlx::PgPool;

async fn connect_to_db() -> Result<PgPool, sqlx::Error> {
    // SAFE: database URL loaded from environment variable; credentials never hardcoded
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL environment variable must be set");

    PgPool::connect(&database_url).await
}

#[tokio::main]
async fn main() {
    match connect_to_db().await {
        Ok(pool) => {
            println!("Connected to database");
            pool.close().await;
        }
        Err(e) => eprintln!("Connection error: {}", e),
    }
}
