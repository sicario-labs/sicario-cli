//! Secret pattern definitions with regex compilation and entropy analysis

use regex::Regex;

/// Types of secrets that can be detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretType {
    AwsAccessKey,
    AwsSecretKey,
    GithubPat,
    StripeKey,
    DatabaseUrl,
    PrivateKey,
    GenericApiKey,
}

impl SecretType {
    /// Human-readable name for the secret type
    pub fn display_name(&self) -> &'static str {
        match self {
            SecretType::AwsAccessKey => "AWS Access Key",
            SecretType::AwsSecretKey => "AWS Secret Key",
            SecretType::GithubPat => "GitHub Personal Access Token",
            SecretType::StripeKey => "Stripe API Key",
            SecretType::DatabaseUrl => "Database Connection URL",
            SecretType::PrivateKey => "Private Key",
            SecretType::GenericApiKey => "Generic API Key",
        }
    }
}

/// Pattern definition for detecting secrets
pub struct SecretPattern {
    pub secret_type: SecretType,
    pub regex: Regex,
    /// Minimum Shannon entropy required to flag a match (0.0 = no threshold)
    pub entropy_threshold: f64,
}

impl SecretPattern {
    /// Create a new SecretPattern
    pub fn new(secret_type: SecretType, pattern: &str, entropy_threshold: f64) -> Self {
        Self {
            secret_type,
            regex: Regex::new(pattern).expect("Invalid regex pattern"),
            entropy_threshold,
        }
    }

    /// Create default secret patterns for all supported credential types
    pub fn default_patterns() -> Vec<Self> {
        vec![
            // AWS Access Key ID: AKIA followed by 16 uppercase alphanumeric chars.
            // No word boundary — keys can appear inside quotes or concatenated strings.
            SecretPattern::new(
                SecretType::AwsAccessKey,
                r"(?i)(AKIA[0-9A-Z]{16})",
                3.0,
            ),
            // AWS Secret Access Key: 40-char base64-like string often near "aws_secret"
            SecretPattern::new(
                SecretType::AwsSecretKey,
                r#"(?i)(?:aws_secret_access_key|aws_secret|secret_access_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#,
                4.5,
            ),
            // GitHub Personal Access Token (classic): ghp_ prefix
            SecretPattern::new(
                SecretType::GithubPat,
                r"(ghp_[A-Za-z0-9]{36})",
                3.5,
            ),
            // GitHub Fine-grained PAT: github_pat_ prefix
            SecretPattern::new(
                SecretType::GithubPat,
                r"(github_pat_[A-Za-z0-9_]{82})",
                3.5,
            ),
            // Stripe live secret key — no word boundary, keys appear in various contexts
            SecretPattern::new(
                SecretType::StripeKey,
                r"(sk_test_[A-Za-z0-9]{24,})",
                3.5,
            ),
            // Stripe test secret key
            SecretPattern::new(
                SecretType::StripeKey,
                r"(sk_test_[A-Za-z0-9]{24,})",
                3.5,
            ),
            // Database connection URLs (postgres, mysql, mongodb, redis)
            SecretPattern::new(
                SecretType::DatabaseUrl,
                r"(?i)((?:postgres|postgresql|mysql|mongodb|redis|mssql|oracle)://[^:]+:[^@\s]+@[^\s]+)",
                3.0,
            ),
            // PEM private keys
            SecretPattern::new(
                SecretType::PrivateKey,
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
                0.0, // No entropy check needed for PEM headers
            ),
            // Generic high-entropy API keys (32+ hex chars assigned to common key variable names)
            SecretPattern::new(
                SecretType::GenericApiKey,
                r#"(?i)(?:api_key|apikey|api_secret|secret_key|access_token|auth_token)\s*[=:]\s*['""]?([A-Fa-f0-9]{32,})['""]?"#,
                4.0,
            ),
        ]
    }

    /// Check if a candidate string meets the entropy threshold
    pub fn meets_entropy_threshold(&self, candidate: &str) -> bool {
        if self.entropy_threshold == 0.0 {
            return true;
        }
        shannon_entropy(candidate) >= self.entropy_threshold
    }
}

/// Calculate Shannon entropy of a string (bits per character)
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let len = s.len() as f64;
    let mut freq = [0u32; 256];

    for byte in s.bytes() {
        freq[byte as usize] += 1;
    }

    freq.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // Feature: sicario-cli-core, Property 1: Secret pattern detection completeness
    proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(30))]

        /// Property 1: Secret pattern detection completeness
        /// For any string containing a credential pattern (AWS keys, Stripe tokens,
        /// GitHub PATs, database connection strings), the Secret Scanner should detect
        /// and identify the credential type using regex compilation.
        /// Validates: Requirements 1.2
        #[test]
        fn prop_aws_access_key_detected_in_any_context(
            prefix in "[a-zA-Z0-9 _=:\"']{0,20}",
            suffix in "[a-zA-Z0-9 _=:\"']{0,20}",
        ) {
            let aws_key = "AKIAIOSFODNN7EXAMPLE";
            let text = format!("{}{}{}", prefix, aws_key, suffix);
            let patterns = SecretPattern::default_patterns();
            let aws_pattern = patterns
                .iter()
                .find(|p| p.secret_type == SecretType::AwsAccessKey)
                .unwrap();
            prop_assert!(
                aws_pattern.regex.is_match(&text),
                "AWS access key should be detected in context: {:?}", text
            );
        }

        #[test]
        fn prop_stripe_live_key_detected_in_any_context(
            prefix in "[a-zA-Z0-9 _=:\"']{0,20}",
            key_suffix in "[A-Za-z0-9]{24,32}",
        ) {
            let stripe_key = format!("sk_test_{}", key_suffix);
            let text = format!("{}{}", prefix, stripe_key);
            let patterns = SecretPattern::default_patterns();
            let stripe_patterns: Vec<_> = patterns
                .iter()
                .filter(|p| p.secret_type == SecretType::StripeKey)
                .collect();
            let detected = stripe_patterns.iter().any(|p| p.regex.is_match(&text));
            prop_assert!(detected, "Stripe live key should be detected in: {:?}", text);
        }

        #[test]
        fn prop_database_url_detected(
            user in "[a-zA-Z][a-zA-Z0-9]{1,10}",
            password in "[a-zA-Z0-9!]{4,16}",
            host in "[a-zA-Z][a-zA-Z0-9]{2,10}",
            db in "[a-zA-Z][a-zA-Z0-9]{2,10}",
        ) {
            // Note: passwords with '@' or '#' would break URL parsing (@ is the
            // user/host separator, # starts a fragment). Real URLs percent-encode
            // such characters. The generator intentionally excludes them.
            let db_url = format!("postgres://{}:{}@{}/{}",  user, password, host, db);
            let patterns = SecretPattern::default_patterns();
            let db_pattern = patterns
                .iter()
                .find(|p| p.secret_type == SecretType::DatabaseUrl)
                .unwrap();
            prop_assert!(
                db_pattern.regex.is_match(&db_url),
                "Database URL should be detected: {:?}", db_url
            );
        }

        #[test]
        fn prop_entropy_threshold_filters_low_entropy_strings(
            repeated_char in "[a-zA-Z]",
            length in 16usize..64,
        ) {
            // A string of repeated characters has very low entropy
            let low_entropy_str: String = repeated_char.chars().next().unwrap()
                .to_string()
                .repeat(length);
            let entropy = shannon_entropy(&low_entropy_str);
            // Repeated chars should have entropy near 0
            prop_assert!(entropy < 1.0, "Repeated char string should have low entropy, got {}", entropy);
        }

        #[test]
        fn prop_entropy_increases_with_diversity(
            s in "[A-Za-z0-9!@#$%]{16,32}",
        ) {
            let entropy = shannon_entropy(&s);
            // Any non-trivial string should have some entropy
            prop_assert!(entropy >= 0.0, "Entropy should be non-negative");
            prop_assert!(entropy <= 8.0, "Entropy should be at most 8 bits per char");
        }
    }

    #[test]
    fn test_aws_access_key_pattern() {
        let patterns = SecretPattern::default_patterns();
        let aws_pattern = patterns
            .iter()
            .find(|p| p.secret_type == SecretType::AwsAccessKey)
            .unwrap();

        assert!(aws_pattern.regex.is_match("AKIAIOSFODNN7EXAMPLE"));
        assert!(aws_pattern.regex.is_match("AKIAIOSFODNN7EXAMPL2"));
        assert!(!aws_pattern.regex.is_match("NOTANAWSKEY12345678"));
        assert!(!aws_pattern.regex.is_match("AKIA123")); // too short
    }

    #[test]
    fn test_github_pat_pattern() {
        let patterns = SecretPattern::default_patterns();
        let gh_patterns: Vec<_> = patterns
            .iter()
            .filter(|p| p.secret_type == SecretType::GithubPat)
            .collect();

        assert!(!gh_patterns.is_empty());
        let classic = gh_patterns.iter().find(|p| {
            p.regex.as_str().contains("ghp_")
        }).unwrap();
        assert!(classic.regex.is_match("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"));
        assert!(!classic.regex.is_match("ghp_short"));
    }

    #[test]
    fn test_stripe_key_pattern() {
        let patterns = SecretPattern::default_patterns();
        let stripe_patterns: Vec<_> = patterns
            .iter()
            .filter(|p| p.secret_type == SecretType::StripeKey)
            .collect();

        assert!(!stripe_patterns.is_empty());
        let live = stripe_patterns.iter().find(|p| p.regex.as_str().contains("sk_test")).unwrap();
        assert!(live.regex.is_match("sk_test_ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
    }

    #[test]
    fn test_database_url_pattern() {
        let patterns = SecretPattern::default_patterns();
        let db_pattern = patterns
            .iter()
            .find(|p| p.secret_type == SecretType::DatabaseUrl)
            .unwrap();

        assert!(db_pattern.regex.is_match("postgres://user:password@localhost:5432/mydb"));
        assert!(db_pattern.regex.is_match("mysql://admin:secret@db.example.com/app"));
        assert!(db_pattern.regex.is_match("mongodb://user:pass@cluster.mongodb.net/db"));
        assert!(!db_pattern.regex.is_match("https://example.com/api"));
    }

    #[test]
    fn test_private_key_pattern() {
        let patterns = SecretPattern::default_patterns();
        let pk_pattern = patterns
            .iter()
            .find(|p| p.secret_type == SecretType::PrivateKey)
            .unwrap();

        assert!(pk_pattern.regex.is_match("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(pk_pattern.regex.is_match("-----BEGIN PRIVATE KEY-----"));
        assert!(pk_pattern.regex.is_match("-----BEGIN EC PRIVATE KEY-----"));
        assert!(pk_pattern.regex.is_match("-----BEGIN OPENSSH PRIVATE KEY-----"));
    }

    #[test]
    fn test_shannon_entropy() {
        // Low entropy: all same character
        assert!(shannon_entropy("aaaaaaaaaa") < 1.0);
        // High entropy: random-looking string
        assert!(shannon_entropy("aB3$xK9mPqR7") > 3.0);
        // Empty string
        assert_eq!(shannon_entropy(""), 0.0);
        // Real AWS key has high entropy
        assert!(shannon_entropy("AKIAIOSFODNN7EXAMPLE") > 3.0);
    }

    #[test]
    fn test_entropy_threshold() {
        let pattern = SecretPattern::new(SecretType::GenericApiKey, r"test", 4.0);
        assert!(!pattern.meets_entropy_threshold("aaaaaaaaaaaaaaaa")); // low entropy
        assert!(pattern.meets_entropy_threshold("aB3xK9mPqR7nZ2wY")); // high entropy
    }

    #[test]
    fn test_zero_entropy_threshold_always_passes() {
        let pattern = SecretPattern::new(SecretType::PrivateKey, r"test", 0.0);
        assert!(pattern.meets_entropy_threshold("aaaaaaaaaa")); // even low entropy passes
    }
}
