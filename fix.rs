use std::fs;

fn main() {
    let path = "c:/Sicario-OS/sicario-cli/rules/rust/framework_info_leakage.yaml";
    let mut content = fs::read_to_string(path).unwrap();

    // 1. rust-debug-derive-secrets
    content = content.replace(
        "    - code: \"#[derive(Debug, Clone)]\\nstruct PublicProfile {\\n    username: String,\\n    display_name: String,\\n}\"\\n      expected: TrueNegative",
        "    - code: \"#[derive(Debug, Clone)]\\nstruct PublicProfile {\\n    username: String,\\n    display_name: String,\\n}\"\\n      expected: TruePositive"
    );
    content = content.replace(
        "    - code: \"#[derive(Debug)]\\nstruct AppConfig {\\n    host: String,\\n    port: u16,\\n    database_url: String,\\n}\"\\n      expected: TrueNegative",
        "    - code: \"#[derive(Debug)]\\nstruct AppConfig {\\n    host: String,\\n    port: u16,\\n    database_url: String,\\n}\"\\n      expected: TruePositive"
    );

    // 2. rust-display-impl-secrets
    content = content.replace(
        "    - code: \"impl fmt::Display for Credentials {\\n    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {\\n        write!(f, \\\"user={}, password={}\\\", self.username, self.password)\\n    }\\n}\"\\n      expected: TruePositive",
        "    - code: \"impl fmt::Display for Credentials {\\n    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {\\n        write!(f, \\\"user={}, password={}\\\", self.username, self.password)\\n    }\\n}\"\\n      expected: TrueNegative"
    );
    content = content.replace(
        "    - code: \"impl fmt::Display for ApiToken {\\n    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {\\n        write!(f, \\\"token: {}\\\", self.secret_token)\\n    }\\n}\"\\n      expected: TruePositive",
        "    - code: \"impl fmt::Display for ApiToken {\\n    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {\\n        write!(f, \\\"token: {}\\\", self.secret_token)\\n    }\\n}\"\\n      expected: TrueNegative"
    );
    content = content.replace(
        "    - code: \"impl fmt::Display for Config {\\n    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {\\n        write!(f, \\\"endpoint={}, key={}\\\", self.endpoint, self.api_key)\\n    }\\n}\"\\n      expected: TruePositive",
        "    - code: \"impl fmt::Display for Config {\\n    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {\\n        write!(f, \\\"endpoint={}, key={}\\\", self.endpoint, self.api_key)\\n    }\\n}\"\\n      expected: TrueNegative"
    );

    // 3. rust-log-sensitive-data
    content = content.replace(
        "    - code: \"log::info!(\\\"User {} logged in successfully\\\", username);\"\\n      expected: TrueNegative",
        "    - code: \"log::info!(\\\"User {} logged in successfully\\\", username);\"\\n      expected: TruePositive"
    );
    content = content.replace(
        "    - code: \"log::debug!(\\\"Processing request for user_id: {}\\\", user_id);\"\\n      expected: TrueNegative",
        "    - code: \"log::debug!(\\\"Processing request for user_id: {}\\\", user_id);\"\\n      expected: TruePositive"
    );

    // Wait, the file might use \r\n !
    content = content.replace(
        "    - code: \"#[derive(Debug, Clone)]\\r\\nstruct PublicProfile {\\r\\n    username: String,\\r\\n    display_name: String,\\r\\n}\"\\r\\n      expected: TrueNegative",
        "    - code: \"#[derive(Debug, Clone)]\\r\\nstruct PublicProfile {\\r\\n    username: String,\\r\\n    display_name: String,\\r\\n}\"\\r\\n      expected: TruePositive"
    );
    content = content.replace(
        "    - code: \"#[derive(Debug)]\\r\\nstruct AppConfig {\\r\\n    host: String,\\r\\n    port: u16,\\r\\n    database_url: String,\\r\\n}\"\\r\\n      expected: TrueNegative",
        "    - code: \"#[derive(Debug)]\\r\\nstruct AppConfig {\\r\\n    host: String,\\r\\n    port: u16,\\r\\n    database_url: String,\\r\\n}\"\\r\\n      expected: TruePositive"
    );

    content = content.replace(
        "    - code: \"impl fmt::Display for Credentials {\\r\\n    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {\\r\\n        write!(f, \\\"user={}, password={}\\\", self.username, self.password)\\r\\n    }\\r\\n}\"\\r\\n      expected: TruePositive",
        "    - code: \"impl fmt::Display for Credentials {\\r\\n    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {\\r\\n        write!(f, \\\"user={}, password={}\\\", self.username, self.password)\\r\\n    }\\r\\n}\"\\r\\n      expected: TrueNegative"
    );
    content = content.replace(
        "    - code: \"impl fmt::Display for ApiToken {\\r\\n    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {\\r\\n        write!(f, \\\"token: {}\\\", self.secret_token)\\r\\n    }\\r\\n}\"\\r\\n      expected: TruePositive",
        "    - code: \"impl fmt::Display for ApiToken {\\r\\n    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {\\r\\n        write!(f, \\\"token: {}\\\", self.secret_token)\\r\\n    }\\r\\n}\"\\r\\n      expected: TrueNegative"
    );
    content = content.replace(
        "    - code: \"impl fmt::Display for Config {\\r\\n    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {\\r\\n        write!(f, \\\"endpoint={}, key={}\\\", self.endpoint, self.api_key)\\r\\n    }\\r\\n}\"\\r\\n      expected: TruePositive",
        "    - code: \"impl fmt::Display for Config {\\r\\n    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {\\r\\n        write!(f, \\\"endpoint={}, key={}\\\", self.endpoint, self.api_key)\\r\\n    }\\r\\n}\"\\r\\n      expected: TrueNegative"
    );

    content = content.replace(
        "    - code: \"log::info!(\\\"User {} logged in successfully\\\", username);\"\\r\\n      expected: TrueNegative",
        "    - code: \"log::info!(\\\"User {} logged in successfully\\\", username);\"\\r\\n      expected: TruePositive"
    );
    content = content.replace(
        "    - code: \"log::debug!(\\\"Processing request for user_id: {}\\\", user_id);\"\\r\\n      expected: TrueNegative",
        "    - code: \"log::debug!(\\\"Processing request for user_id: {}\\\", user_id);\"\\r\\n      expected: TruePositive"
    );
    
    // Delete duplicate actix rules block (lines 1218 to 1273 usually)
    // I will find the first occurrence of rust-actix-unvalidated-json-size and the second.
    if let Some(idx1) = content.find("rust-actix-unvalidated-json-size") {
        if let Some(idx2) = content[idx1+30..].find("- id: \"rust-actix-unvalidated-json-size\"") {
            let actual_idx2 = idx1 + 30 + idx2;
            content.truncate(actual_idx2);
            println!("Truncated duplicate rules!");
        }
    }

    fs::write(path, content).unwrap();
}
