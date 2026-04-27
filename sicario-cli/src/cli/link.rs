//! Link subcommand for associating a project with a project ID.

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

/// Arguments for the `link` subcommand.
#[derive(Parser, Debug)]
pub struct LinkArgs {
    /// Project ID to link to
    #[arg(long)]
    pub project: Option<String>,
}

/// Link the current project to a Sicario Cloud project.
///
/// Writes the project ID to `~/.sicario/config.toml` under key `project_id`.
pub fn cmd_link(args: LinkArgs) -> Result<()> {
    let project_id = args.project.ok_or_else(|| {
        anyhow::anyhow!(
            "Project ID is required. Use `sicario link --project=<PROJECT_ID>`"
        )
    })?;

    // Write to global config (~/.sicario/config.toml)
    let config_path = crate::config::global_config_path()
        .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;

    // Ensure the directory exists
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Load existing config or start fresh
    let mut config = crate::config::global_config::load_global_config()
        .unwrap_or_default();

    // Store project_id in extra fields (since GlobalConfig doesn't have a project_id field)
    config.extra.insert(
        "project_id".to_string(),
        serde_yaml::Value::String(project_id.clone()),
    );

    // Serialize to TOML
    let toml_str = toml::to_string_pretty(&config)?;

    std::fs::write(&config_path, &toml_str)?;

    // Restrict permissions to owner-only (0600) on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&config_path, perms)?;
    }

    eprintln!("Linked to project {project_id}. Telemetry will be routed to this project.");

    Ok(())
}
