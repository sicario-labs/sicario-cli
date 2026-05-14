// SAFE: rust-command-web-input — URL validated against allowlist before outbound request
// Rule: rust-command-web-input | CWE-918 | Expected: TrueNegative

use std::collections::HashSet;

async fn fetch_allowed_url(target_url: &str) -> Result<String, String> {
    let allowed_hosts: HashSet<&str> = ["api.example.com", "data.example.com"].iter().cloned().collect();

    // SAFE: parse and validate the URL against an allowlist of trusted hosts
    let parsed = url::Url::parse(target_url).map_err(|e| e.to_string())?;
    let host = parsed.host_str().ok_or("No host in URL")?;

    if !allowed_hosts.contains(host) {
        return Err(format!("Host '{}' is not allowed", host));
    }

    let response = reqwest::get(parsed).await.map_err(|e| e.to_string())?;
    response.text().await.map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() {
    let url = std::env::args().nth(1).unwrap_or_else(|| "https://api.example.com/data".to_string());
    match fetch_allowed_url(&url).await {
        Ok(body) => println!("{}", body),
        Err(e) => eprintln!("Error: {}", e),
    }
}
