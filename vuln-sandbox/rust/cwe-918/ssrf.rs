// VULNERABLE: rust-command-web-input — HTTP request to user-controlled URL
// Rule: rust-command-web-input | CWE-918 | Severity: CRITICAL

use reqwest::Client;

async fn fetch_url(user_url: &str) -> Result<String, reqwest::Error> {
    let client = Client::new();

    // VULNERABLE: user-controlled URL used for outbound HTTP request
    // An attacker can pass: http://169.254.169.254/latest/meta-data to access cloud metadata
    let response = client.get(user_url).send().await?;
    let body = response.text().await?;
    Ok(body)
}

#[tokio::main]
async fn main() {
    // Simulating user input from an HTTP request parameter
    let url = std::env::args().nth(1).unwrap_or_default();
    match fetch_url(&url).await {
        Ok(body) => println!("{}", body),
        Err(e) => eprintln!("error: {}", e),
    }
}
