use std::process::Command;
fn main() {
    Command::new(std::env::var("EDITOR").unwrap()).spawn();
}
