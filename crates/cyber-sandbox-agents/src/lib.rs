//! Registration of a sandbox with the host's agents.
//!
//! Both Claude Code and Codex can keep their model side — and with it the credentials —
//! on the host while running their tool side over SSH. This crate writes the two
//! configuration entries that arrange it, so the sandbox never needs a token of its own
//! and never needs egress to be usable as a research environment.
//!
//! Existing configuration is preserved: Claude's settings are edited as JSON and Codex's
//! files as TOML documents, so hand-written entries and comments survive.

mod claude;
mod codex;
mod endpoint;
mod error;
mod toml_file;

pub use claude::{ClaudeSettings, SshConfig};
pub use codex::{Codex, CodexConfig, CodexEnvironments};
pub use endpoint::SandboxEndpoint;
pub use error::AgentError;

use std::path::{Path, PathBuf};

/// The two host-side configuration files a sandbox registers itself in.
#[derive(Debug, Clone)]
pub struct AgentIntegration {
    claude: ClaudeSettings,
    codex: Codex,
}

impl AgentIntegration {
    /// Locates both configuration files under `home`.
    #[must_use]
    pub fn for_home(home: &Path) -> Self {
        Self {
            claude: ClaudeSettings::new(home.join(".claude").join("settings.json")),
            codex: Codex::for_home(home),
        }
    }

    /// Claude Code's settings, where the sandbox appears as an SSH configuration.
    #[must_use]
    pub fn claude(&self) -> &ClaudeSettings {
        &self.claude
    }

    /// Codex's configuration, where the sandbox appears as a stdio-over-SSH environment.
    #[must_use]
    pub fn codex(&self) -> &Codex {
        &self.codex
    }

    /// Removes the entries belonging to `id` from both agents.
    ///
    /// # Errors
    /// Fails when either file cannot be read, parsed or written.
    pub async fn unregister(&self, id: &str) -> Result<(), AgentError> {
        self.claude.unregister(id).await?;
        self.codex.unregister(id).await
    }
}

/// Where the sandbox's own SSH material lives on the host.
#[must_use]
pub fn key_directory(home: &Path) -> PathBuf {
    home.join(".cyber-sandbox").join("keys")
}

/// Where the host keys sandboxes present are remembered, one file per sandbox.
#[must_use]
pub fn known_hosts_directory(home: &Path) -> PathBuf {
    home.join(".cyber-sandbox").join("known_hosts")
}

/// Where the directories agents are pointed at live, one per sandbox.
///
/// An agent whose model side runs on the host resolves the directory it is working in
/// against the host's own filesystem, then asks the sandbox to execute there. So the path
/// it is given has to exist on both sides — and the sandbox aliases its copy to the work
/// directory, which is why the host's copy stays empty. Nothing is shared through it: it
/// exists only so that the path the agent validates is a path the sandbox can honour.
#[must_use]
pub fn work_alias_directory(home: &Path) -> PathBuf {
    home.join(".cyber-sandbox").join("work")
}

/// Replaces `path` with `contents`, creating the parent directory and never leaving a
/// half-written configuration behind if the process dies mid-write.
async fn write_file(path: &Path, contents: &str) -> Result<(), AgentError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|source| AgentError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
    }
    let staging = path.with_extension("cyber-sandbox-staging");
    tokio::fs::write(&staging, contents)
        .await
        .map_err(|source| AgentError::Io {
            path: staging.clone(),
            source,
        })?;
    tokio::fs::rename(&staging, path)
        .await
        .map_err(|source| AgentError::Io {
            path: path.to_path_buf(),
            source,
        })
}
