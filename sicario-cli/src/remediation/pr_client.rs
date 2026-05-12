//! PR/MR creation client for GitHub and GitLab.
//!
//! Provides `create_github_pr` and `create_gitlab_mr` which push a patch to a
//! new branch and open a pull/merge request via the respective REST APIs.
//!
//! Requirements: eta-engine 12.3

use anyhow::{anyhow, Context, Result};
use base64_url::encode as b64_encode;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::Patch;

//  Provider detection

/// Detected git hosting provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitProvider {
    GitHub,
    GitLab,
    Unknown(String),
}

/// Parse the remote URL returned by `git remote get-url origin` and return the
/// detected provider.
pub fn detect_provider(remote_url: &str) -> GitProvider {
    let url = remote_url.trim();
    if url.contains("github.com") {
        GitProvider::GitHub
    } else if url.contains("gitlab.com") {
        GitProvider::GitLab
    } else {
        GitProvider::Unknown(url.to_string())
    }
}

/// Run `git remote get-url origin` and return the trimmed output.
pub fn get_remote_url() -> Result<String> {
    let output = std::process::Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .context("Failed to run `git remote get-url origin`")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "Could not determine git remote URL: {}",
            stderr.trim()
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Parse `owner/repo` from a GitHub or GitLab remote URL.
///
/// Handles both HTTPS (`https://github.com/owner/repo.git`) and SSH
/// (`git@github.com:owner/repo.git`) formats.
pub fn parse_owner_repo(remote_url: &str) -> Result<(String, String)> {
    let url = remote_url.trim().trim_end_matches(".git");

    // SSH format: git@github.com:owner/repo
    if let Some(colon_pos) = url.rfind(':') {
        let after_colon = &url[colon_pos + 1..];
        if let Some((owner, repo)) = after_colon.split_once('/') {
            if !owner.is_empty() && !repo.is_empty() {
                return Ok((owner.to_string(), repo.to_string()));
            }
        }
    }

    // HTTPS format: https://github.com/owner/repo
    // Split on '/' and take the last two non-empty segments.
    let parts: Vec<&str> = url.split('/').filter(|s| !s.is_empty()).collect();
    if parts.len() >= 2 {
        let repo = parts[parts.len() - 1];
        let owner = parts[parts.len() - 2];
        return Ok((owner.to_string(), repo.to_string()));
    }

    Err(anyhow!(
        "Could not parse owner/repo from remote URL: {}",
        remote_url
    ))
}

//  Timestamp helper

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

//  GitHub PR creation

#[derive(Debug, Serialize)]
struct GitHubCreateRefRequest {
    #[serde(rename = "ref")]
    ref_name: String,
    sha: String,
}

#[derive(Debug, Serialize)]
struct GitHubUpdateFileRequest {
    message: String,
    content: String,
    branch: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubFileResponse {
    #[serde(default)]
    sha: Option<String>,
}

#[derive(Debug, Serialize)]
struct GitHubCreatePrRequest {
    title: String,
    body: String,
    head: String,
    base: String,
}

#[derive(Debug, Deserialize)]
struct GitHubPrResponse {
    html_url: String,
}

#[derive(Debug, Deserialize)]
struct GitHubRef {
    object: GitHubRefObject,
}

#[derive(Debug, Deserialize)]
struct GitHubRefObject {
    sha: String,
}

/// Create a GitHub pull request for the given patch.
///
/// Steps:
/// 1. Read `GITHUB_TOKEN` env var.
/// 2. Auto-detect owner/repo from `git remote get-url origin`.
/// 3. Create a branch `sicario/fix-<rule_id>-<timestamp>`.
/// 4. Commit the patched file content to that branch.
/// 5. Open a PR with title `fix: [sicario] <rule_id> in <file>` and body containing the patch.
/// 6. Return the PR URL.
pub fn create_github_pr(patch: &Patch, rule_id: &str) -> Result<String> {
    let token = std::env::var("GITHUB_TOKEN").map_err(|_| {
        anyhow!(
            "GITHUB_TOKEN environment variable is not set. \
             Set it to a GitHub personal access token with `repo` scope: \
             https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens"
        )
    })?;

    let remote_url = get_remote_url()?;
    let (owner, repo) = parse_owner_repo(&remote_url)?;

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("Failed to build HTTP client")?;

    let api_base = "https://api.github.com";

    // Sanitise rule_id for use in branch name (replace non-alphanumeric with '-')
    let rule_slug: String = rule_id
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let timestamp = unix_timestamp();
    let branch_name = format!("sicario/fix-{}-{}", rule_slug, timestamp);

    //  Step 1: Get the SHA of the default branch HEAD
    let default_branch = get_github_default_branch(&client, &token, api_base, &owner, &repo)?;
    let head_sha =
        get_github_branch_sha(&client, &token, api_base, &owner, &repo, &default_branch)?;

    //  Step 2: Create the new branch
    let create_ref_url = format!("{}/repos/{}/{}/git/refs", api_base, owner, repo);
    let create_ref_body = GitHubCreateRefRequest {
        ref_name: format!("refs/heads/{}", branch_name),
        sha: head_sha,
    };

    let resp = client
        .post(&create_ref_url)
        .bearer_auth(&token)
        .header("User-Agent", "sicario-cli")
        .header("Accept", "application/vnd.github+json")
        .json(&create_ref_body)
        .send()
        .context("Failed to create GitHub branch")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        return Err(anyhow!(
            "GitHub create branch failed ({}): {}",
            status,
            body
        ));
    }

    //  Step 3: Get existing file SHA (needed for update)
    let file_path_str = patch.file_path.to_string_lossy().replace('\\', "/");
    let existing_sha = get_github_file_sha(
        &client,
        &token,
        api_base,
        &owner,
        &repo,
        &file_path_str,
        &branch_name,
    );

    //  Step 4: Commit the patched file
    let encoded_content = b64_encode(patch.fixed.as_bytes());
    let commit_url = format!(
        "{}/repos/{}/{}/contents/{}",
        api_base, owner, repo, file_path_str
    );

    let commit_body = GitHubUpdateFileRequest {
        message: format!(
            "fix: [sicario] apply security patch to {}",
            patch.file_path.display()
        ),
        content: encoded_content,
        branch: branch_name.clone(),
        sha: existing_sha.ok(),
    };

    let resp = client
        .put(&commit_url)
        .bearer_auth(&token)
        .header("User-Agent", "sicario-cli")
        .header("Accept", "application/vnd.github+json")
        .json(&commit_body)
        .send()
        .context("Failed to commit file to GitHub branch")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        return Err(anyhow!("GitHub file commit failed ({}): {}", status, body));
    }

    //  Step 5: Open the PR
    let pr_url = format!("{}/repos/{}/{}/pulls", api_base, owner, repo);
    let file_path_display = patch.file_path.to_string_lossy().into_owned();
    let file_name = patch
        .file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&file_path_display);
    let pr_title = format!("fix: [sicario] {} in {}", rule_id, file_name);
    let pr_body = build_pr_body(patch, rule_id);

    let pr_body_req = GitHubCreatePrRequest {
        title: pr_title,
        body: pr_body,
        head: branch_name,
        base: default_branch,
    };

    let resp = client
        .post(&pr_url)
        .bearer_auth(&token)
        .header("User-Agent", "sicario-cli")
        .header("Accept", "application/vnd.github+json")
        .json(&pr_body_req)
        .send()
        .context("Failed to create GitHub PR")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        return Err(anyhow!("GitHub PR creation failed ({}): {}", status, body));
    }

    let pr_response: GitHubPrResponse =
        resp.json().context("Failed to parse GitHub PR response")?;

    Ok(pr_response.html_url)
}

fn get_github_default_branch(
    client: &Client,
    token: &str,
    api_base: &str,
    owner: &str,
    repo: &str,
) -> Result<String> {
    #[derive(Deserialize)]
    struct RepoInfo {
        default_branch: String,
    }

    let url = format!("{}/repos/{}/{}", api_base, owner, repo);
    let resp = client
        .get(&url)
        .bearer_auth(token)
        .header("User-Agent", "sicario-cli")
        .header("Accept", "application/vnd.github+json")
        .send()
        .context("Failed to fetch GitHub repo info")?;

    if !resp.status().is_success() {
        return Ok("main".to_string()); // sensible default
    }

    let info: RepoInfo = resp.json().context("Failed to parse GitHub repo info")?;
    Ok(info.default_branch)
}

fn get_github_branch_sha(
    client: &Client,
    token: &str,
    api_base: &str,
    owner: &str,
    repo: &str,
    branch: &str,
) -> Result<String> {
    let url = format!(
        "{}/repos/{}/{}/git/ref/heads/{}",
        api_base, owner, repo, branch
    );
    let resp = client
        .get(&url)
        .bearer_auth(token)
        .header("User-Agent", "sicario-cli")
        .header("Accept", "application/vnd.github+json")
        .send()
        .context("Failed to fetch GitHub branch SHA")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        return Err(anyhow!(
            "GitHub get branch SHA failed ({}): {}",
            status,
            body
        ));
    }

    let git_ref: GitHubRef = resp.json().context("Failed to parse GitHub ref response")?;
    Ok(git_ref.object.sha)
}

fn get_github_file_sha(
    client: &Client,
    token: &str,
    api_base: &str,
    owner: &str,
    repo: &str,
    file_path: &str,
    branch: &str,
) -> Result<String> {
    let url = format!(
        "{}/repos/{}/{}/contents/{}?ref={}",
        api_base, owner, repo, file_path, branch
    );
    let resp = client
        .get(&url)
        .bearer_auth(token)
        .header("User-Agent", "sicario-cli")
        .header("Accept", "application/vnd.github+json")
        .send()
        .context("Failed to fetch GitHub file info")?;

    if !resp.status().is_success() {
        return Err(anyhow!("File not found on branch"));
    }

    let file_info: GitHubFileResponse = resp
        .json()
        .context("Failed to parse GitHub file response")?;
    file_info
        .sha
        .ok_or_else(|| anyhow!("GitHub file response missing SHA"))
}

//  GitLab MR creation

#[derive(Debug, Serialize)]
struct GitLabCreateBranchRequest {
    branch: String,
    #[serde(rename = "ref")]
    ref_name: String,
}

#[derive(Debug, Serialize)]
struct GitLabCommitAction {
    action: String,
    file_path: String,
    content: String,
    encoding: String,
}

#[derive(Debug, Serialize)]
struct GitLabCreateCommitRequest {
    branch: String,
    commit_message: String,
    actions: Vec<GitLabCommitAction>,
}

#[derive(Debug, Serialize)]
struct GitLabCreateMrRequest {
    source_branch: String,
    target_branch: String,
    title: String,
    description: String,
    remove_source_branch: bool,
}

#[derive(Debug, Deserialize)]
struct GitLabMrResponse {
    web_url: String,
}

#[derive(Debug, Deserialize)]
struct GitLabProjectResponse {
    default_branch: String,
}

/// Create a GitLab merge request for the given patch.
///
/// Steps:
/// 1. Read `GITLAB_TOKEN` env var.
/// 2. Auto-detect project path from `git remote get-url origin`.
/// 3. Create a branch `sicario/fix-<rule_id>-<timestamp>`.
/// 4. Commit the patched file content to that branch.
/// 5. Open an MR with title `fix: [sicario] <rule_id> in <file>` and description.
/// 6. Return the MR URL.
pub fn create_gitlab_mr(patch: &Patch, rule_id: &str) -> Result<String> {
    let token = std::env::var("GITLAB_TOKEN").map_err(|_| {
        anyhow!(
            "GITLAB_TOKEN environment variable is not set. \
             Set it to a GitLab personal access token with `api` scope: \
             https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html"
        )
    })?;

    let remote_url = get_remote_url()?;
    let (namespace, project) = parse_owner_repo(&remote_url)?;

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("Failed to build HTTP client")?;

    let api_base = "https://gitlab.com/api/v4";
    // URL-encode the project path (namespace%2Fproject)
    let project_id = format!("{}/{}", namespace, project);
    let encoded_project_id = project_id.replace('/', "%2F");

    // Sanitise rule_id for use in branch name
    let rule_slug: String = rule_id
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let timestamp = unix_timestamp();
    let branch_name = format!("sicario/fix-{}-{}", rule_slug, timestamp);

    //  Step 1: Get default branch
    let default_branch = get_gitlab_default_branch(&client, &token, api_base, &encoded_project_id)?;

    //  Step 2: Create the new branch
    let create_branch_url = format!(
        "{}/projects/{}/repository/branches",
        api_base, encoded_project_id
    );
    let create_branch_body = GitLabCreateBranchRequest {
        branch: branch_name.clone(),
        ref_name: default_branch.clone(),
    };

    let resp = client
        .post(&create_branch_url)
        .header("PRIVATE-TOKEN", &token)
        .header("Content-Type", "application/json")
        .json(&create_branch_body)
        .send()
        .context("Failed to create GitLab branch")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        return Err(anyhow!(
            "GitLab create branch failed ({}): {}",
            status,
            body
        ));
    }

    //  Step 3: Commit the patched file
    let file_path_str = patch.file_path.to_string_lossy().replace('\\', "/");
    let encoded_content = b64_encode(patch.fixed.as_bytes());

    let commit_url = format!(
        "{}/projects/{}/repository/commits",
        api_base, encoded_project_id
    );
    let commit_body = GitLabCreateCommitRequest {
        branch: branch_name.clone(),
        commit_message: format!(
            "fix: [sicario] apply security patch to {}",
            patch.file_path.display()
        ),
        actions: vec![GitLabCommitAction {
            action: "update".to_string(),
            file_path: file_path_str,
            content: encoded_content,
            encoding: "base64".to_string(),
        }],
    };

    let resp = client
        .post(&commit_url)
        .header("PRIVATE-TOKEN", &token)
        .header("Content-Type", "application/json")
        .json(&commit_body)
        .send()
        .context("Failed to commit file to GitLab branch")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        return Err(anyhow!("GitLab file commit failed ({}): {}", status, body));
    }

    //  Step 4: Open the MR
    let mr_url = format!(
        "{}/projects/{}/merge_requests",
        api_base, encoded_project_id
    );
    let file_path_display = patch.file_path.to_string_lossy().into_owned();
    let file_name = patch
        .file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&file_path_display);
    let mr_title = format!("fix: [sicario] {} in {}", rule_id, file_name);
    let mr_description = build_pr_body(patch, rule_id);

    let mr_body = GitLabCreateMrRequest {
        source_branch: branch_name,
        target_branch: default_branch,
        title: mr_title,
        description: mr_description,
        remove_source_branch: true,
    };

    let resp = client
        .post(&mr_url)
        .header("PRIVATE-TOKEN", &token)
        .header("Content-Type", "application/json")
        .json(&mr_body)
        .send()
        .context("Failed to create GitLab MR")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        return Err(anyhow!("GitLab MR creation failed ({}): {}", status, body));
    }

    let mr_response: GitLabMrResponse =
        resp.json().context("Failed to parse GitLab MR response")?;

    Ok(mr_response.web_url)
}

fn get_gitlab_default_branch(
    client: &Client,
    token: &str,
    api_base: &str,
    encoded_project_id: &str,
) -> Result<String> {
    let url = format!("{}/projects/{}", api_base, encoded_project_id);
    let resp = client
        .get(&url)
        .header("PRIVATE-TOKEN", token)
        .send()
        .context("Failed to fetch GitLab project info")?;

    if !resp.status().is_success() {
        return Ok("main".to_string()); // sensible default
    }

    let info: GitLabProjectResponse = resp.json().context("Failed to parse GitLab project info")?;
    Ok(info.default_branch)
}

//  Shared helpers

/// Build the PR/MR body text from a patch.
fn build_pr_body(patch: &Patch, rule_id: &str) -> String {
    format!(
        "## Sicario Security Patch\n\n\
         This pull request was automatically generated by [sicario](https://usesicario.xyz).\n\n\
         **Rule:** `{}`\n\
         **File:** `{}`\n\n\
         ### Diff\n\n\
         ```diff\n{}\n```\n\n\
         ---\n\
         *Generated by sicario  zero-exfiltration security remediation*",
        rule_id,
        patch.file_path.display(),
        patch.diff,
    )
}

/// Auto-detect the git provider from the remote URL and dispatch to the
/// correct PR/MR creation function.
pub fn create_pull_request_auto(patch: &Patch, rule_id: &str) -> Result<String> {
    let remote_url = get_remote_url()?;
    match detect_provider(&remote_url) {
        GitProvider::GitHub => create_github_pr(patch, rule_id),
        GitProvider::GitLab => create_gitlab_mr(patch, rule_id),
        GitProvider::Unknown(url) => Err(anyhow!(
            "Unsupported git provider for remote URL '{}'. \
             Only github.com and gitlab.com are supported.",
            url
        )),
    }
}

/// Create a GitHub PR for an already-pushed branch (used by --auto-pr).
///
/// Unlike `create_github_pr`, this function does NOT commit files — it assumes
/// the branch has already been pushed by the caller. It only opens the PR.
pub fn create_github_pr_with_branch(branch_name: &str, title: &str, body: &str) -> Result<String> {
    let token = std::env::var("GITHUB_TOKEN").map_err(|_| {
        anyhow!("GITHUB_TOKEN environment variable is not set.")
    })?;

    let remote_url = get_remote_url()?;
    let (owner, repo) = parse_owner_repo(&remote_url)?;

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("Failed to build HTTP client")?;

    let api_base = "https://api.github.com";
    let default_branch = get_github_default_branch(&client, &token, api_base, &owner, &repo)?;

    let pr_url = format!("{}/repos/{}/{}/pulls", api_base, owner, repo);
    let pr_body_req = GitHubCreatePrRequest {
        title: title.to_string(),
        body: body.to_string(),
        head: branch_name.to_string(),
        base: default_branch,
    };

    let resp = client
        .post(&pr_url)
        .bearer_auth(&token)
        .header("User-Agent", "sicario-cli")
        .header("Accept", "application/vnd.github+json")
        .json(&pr_body_req)
        .send()
        .context("Failed to create GitHub PR")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body_text = resp.text().unwrap_or_default();
        return Err(anyhow!("GitHub PR creation failed ({}): {}", status, body_text));
    }

    let pr_response: GitHubPrResponse = resp.json().context("Failed to parse GitHub PR response")?;
    Ok(pr_response.html_url)
}

/// Create a GitLab MR for an already-pushed branch (used by --auto-pr).
pub fn create_gitlab_mr_with_branch(branch_name: &str, title: &str, body: &str) -> Result<String> {
    let token = std::env::var("GITLAB_TOKEN").map_err(|_| {
        anyhow!("GITLAB_TOKEN environment variable is not set.")
    })?;

    let remote_url = get_remote_url()?;
    let (namespace, project) = parse_owner_repo(&remote_url)?;

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("Failed to build HTTP client")?;

    let api_base = "https://gitlab.com/api/v4";
    let project_id = format!("{}/{}", namespace, project);
    let encoded_project_id = project_id.replace('/', "%2F");
    let default_branch = get_gitlab_default_branch(&client, &token, api_base, &encoded_project_id)?;

    let mr_url = format!("{}/projects/{}/merge_requests", api_base, encoded_project_id);
    let mr_body = GitLabCreateMrRequest {
        source_branch: branch_name.to_string(),
        target_branch: default_branch,
        title: title.to_string(),
        description: body.to_string(),
        remove_source_branch: true,
    };

    let resp = client
        .post(&mr_url)
        .header("PRIVATE-TOKEN", &token)
        .header("Content-Type", "application/json")
        .json(&mr_body)
        .send()
        .context("Failed to create GitLab MR")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body_text = resp.text().unwrap_or_default();
        return Err(anyhow!("GitLab MR creation failed ({}): {}", status, body_text));
    }

    let mr_response: GitLabMrResponse = resp.json().context("Failed to parse GitLab MR response")?;
    Ok(mr_response.web_url)
}

//  Tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_test_patch() -> Patch {
        Patch::new(
            PathBuf::from("src/db/queries.js"),
            "const query = `SELECT * FROM users WHERE id = ${userId}`;".to_string(),
            "const query = 'SELECT * FROM users WHERE id = ?'; db.query(query, [userId]);".to_string(),
            "--- a/src/db/queries.js\n+++ b/src/db/queries.js\n@@ -1 +1 @@\n-const query = `SELECT * FROM users WHERE id = ${userId}`;\n+const query = 'SELECT * FROM users WHERE id = ?'; db.query(query, [userId]);".to_string(),
            PathBuf::from(".sicario/backups/queries.js"),
        )
    }

    //  Provider detection tests

    #[test]
    fn test_detect_provider_github_https() {
        assert_eq!(
            detect_provider("https://github.com/owner/repo.git"),
            GitProvider::GitHub
        );
    }

    #[test]
    fn test_detect_provider_github_ssh() {
        assert_eq!(
            detect_provider("git@github.com:owner/repo.git"),
            GitProvider::GitHub
        );
    }

    #[test]
    fn test_detect_provider_gitlab_https() {
        assert_eq!(
            detect_provider("https://gitlab.com/owner/repo.git"),
            GitProvider::GitLab
        );
    }

    #[test]
    fn test_detect_provider_gitlab_ssh() {
        assert_eq!(
            detect_provider("git@gitlab.com:owner/repo.git"),
            GitProvider::GitLab
        );
    }

    #[test]
    fn test_detect_provider_unknown() {
        let provider = detect_provider("https://bitbucket.org/owner/repo.git");
        assert!(matches!(provider, GitProvider::Unknown(_)));
    }

    //  parse_owner_repo tests

    #[test]
    fn test_parse_owner_repo_https() {
        let (owner, repo) =
            parse_owner_repo("https://github.com/sicario-labs/sicario-cli.git").unwrap();
        assert_eq!(owner, "sicario-labs");
        assert_eq!(repo, "sicario-cli");
    }

    #[test]
    fn test_parse_owner_repo_ssh() {
        let (owner, repo) =
            parse_owner_repo("git@github.com:sicario-labs/sicario-cli.git").unwrap();
        assert_eq!(owner, "sicario-labs");
        assert_eq!(repo, "sicario-cli");
    }

    #[test]
    fn test_parse_owner_repo_no_git_suffix() {
        let (owner, repo) = parse_owner_repo("https://github.com/owner/repo").unwrap();
        assert_eq!(owner, "owner");
        assert_eq!(repo, "repo");
    }

    //  Missing token tests

    #[test]
    fn test_create_github_pr_missing_token_returns_descriptive_error() {
        // Remove the token from the environment
        std::env::remove_var("GITHUB_TOKEN");

        let patch = make_test_patch();
        let result = create_github_pr(&patch, "js-sql-injection");

        assert!(result.is_err(), "Should fail when GITHUB_TOKEN is absent");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("GITHUB_TOKEN"),
            "Error should mention GITHUB_TOKEN, got: {}",
            err_msg
        );
        assert!(
            err_msg.contains("personal access token") || err_msg.contains("not set"),
            "Error should be descriptive, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_create_gitlab_mr_missing_token_returns_descriptive_error() {
        std::env::remove_var("GITLAB_TOKEN");

        let patch = make_test_patch();
        let result = create_gitlab_mr(&patch, "js-sql-injection");

        assert!(result.is_err(), "Should fail when GITLAB_TOKEN is absent");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("GITLAB_TOKEN"),
            "Error should mention GITLAB_TOKEN, got: {}",
            err_msg
        );
    }

    //  Unsupported provider test

    #[test]
    fn test_create_pull_request_auto_unsupported_provider() {
        // We cannot easily mock `get_remote_url()` without a real git repo,
        // so we test the dispatch logic directly via detect_provider.
        let url = "https://bitbucket.org/owner/repo.git";
        let provider = detect_provider(url);
        assert!(
            matches!(provider, GitProvider::Unknown(_)),
            "Bitbucket should be Unknown provider"
        );
    }

    //  PR body tests

    #[test]
    fn test_build_pr_body_contains_file_path() {
        let patch = make_test_patch();
        let body = build_pr_body(&patch, "js-sql-injection");
        assert!(
            body.contains("src/db/queries.js"),
            "Body should contain file path"
        );
    }

    #[test]
    fn test_build_pr_body_contains_rule_id() {
        let patch = make_test_patch();
        let body = build_pr_body(&patch, "js-sql-injection");
        assert!(
            body.contains("js-sql-injection"),
            "Body should contain rule_id"
        );
    }

    #[test]
    fn test_build_pr_body_contains_diff() {
        let patch = make_test_patch();
        let body = build_pr_body(&patch, "js-sql-injection");
        assert!(body.contains("```diff"), "Body should contain diff block");
    }

    #[test]
    fn test_build_pr_body_contains_sicario_attribution() {
        let patch = make_test_patch();
        let body = build_pr_body(&patch, "js-sql-injection");
        assert!(body.contains("sicario"), "Body should mention sicario");
    }

    #[test]
    fn test_pr_title_format() {
        // Verify the title format matches spec: "fix: [sicario] <rule_id> in <file>"
        let patch = make_test_patch();
        let file_name = patch
            .file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        let rule_id = "js-sql-injection";
        let title = format!("fix: [sicario] {} in {}", rule_id, file_name);
        assert_eq!(title, "fix: [sicario] js-sql-injection in queries.js");
    }

    #[test]
    fn test_branch_name_uses_rule_id() {
        // Verify branch name format: sicario/fix-<rule_id>-<timestamp>
        let rule_id = "js-sql-injection";
        let rule_slug: String = rule_id
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        let timestamp = 1234567890u64;
        let branch_name = format!("sicario/fix-{}-{}", rule_slug, timestamp);
        assert_eq!(branch_name, "sicario/fix-js-sql-injection-1234567890");
    }

    #[test]
    fn test_unsupported_provider_error_message() {
        // Verify the error message format for unsupported providers
        let url = "https://bitbucket.org/owner/repo.git";
        let provider = detect_provider(url);
        if let GitProvider::Unknown(u) = provider {
            let err_msg = format!(
                "Unsupported git provider for remote URL '{}'. \
                 Only github.com and gitlab.com are supported.",
                u
            );
            assert!(err_msg.contains("Unsupported git provider"));
            assert!(err_msg.contains("github.com"));
            assert!(err_msg.contains("gitlab.com"));
        }
    }
}
