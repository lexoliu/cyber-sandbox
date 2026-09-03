//! Registration of a sandbox with the host's agents.
//!
//! Both Claude Code and Codex can keep their model side — and with it the credentials —
//! on the host while running their tool side over SSH. This crate writes the two
//! configuration entries that arrange it, so the sandbox never needs a token of its own
//! and never needs egress to be usable as a research environment.
//!
//! Existing configuration is preserved: Claude's settings are edited as JSON and Codex's
//! environments as a TOML document, so hand-written entries and comments survive.

mod claude;
mod codex;
mod endpoint;
mod error;

pub use claude::{ClaudeSettings, SshConfig};
pub use codex::CodexEnvironments;
pub use endpoint::SandboxEndpoint;
pub use error::AgentError;

use std::path::{Path, PathBuf};

/// The two host-side configuration files a sandbox registers itself in.
#[derive(Debug, Clone)]
pub struct AgentIntegration {
    claude: ClaudeSettings,
    codex: CodexEnvironments,
}

impl AgentIntegration {
    /// Locates both configuration files under `home`.
    #[must_use]
    pub fn for_home(home: &Path) -> Self {
        Self {
            claude: ClaudeSettings::new(home.join(".claude").join("settings.json")),
            codex: CodexEnvironments::new(home.join(".codex").join("environments.toml")),
        }
    }

    /// Path of the Claude Code settings file being edited.
    #[must_use]
    pub fn claude_path(&self) -> &Path {
        self.claude.path()
    }

    /// Path of the Codex environments file being edited.
    #[must_use]
    pub fn codex_path(&self) -> &Path {
        self.codex.path()
    }

    /// Adds or replaces the entry both agents use to reach `endpoint`.
    ///
    /// # Errors
    /// Fails when either file cannot be read, parsed or written.
    pub async fn register(&self, endpoint: &SandboxEndpoint) -> Result<(), AgentError> {
        self.claude.register(endpoint).await?;
        self.codex.register(endpoint).await
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
