fn main() {
    db.execute_unprepared(&format!("DROP TABLE {}", table_name)).await;
}
