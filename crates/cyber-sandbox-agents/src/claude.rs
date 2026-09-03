//! Claude Code's `sshConfigs` entry for a sandbox.
//!
//! Claude Code runs the agent — and therefore the credential — on the host and reaches
//! the sandbox over SSH, exposing its own API socket to the remote side as a forwarded
//! unix socket. Registering a sandbox is a matter of adding one entry to `sshConfigs` in
//! `~/.claude/settings.json`; everything else in the user's settings is left alone.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::fs;

use crate::{endpoint::SandboxEndpoint, error::AgentError, write_file};

/// Settings key holding the list of SSH connections Claude Code offers.
const SSH_CONFIGS: &str = "sshConfigs";

/// One entry of Claude Code's `sshConfigs` array.
///
/// The field names are Claude Code's own settings schema, camel case on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshConfig {
    /// Identifier `claude ssh <id>` takes, and the key entries are matched on.
    pub id: String,
    /// Name shown in Claude Code's connection picker.
    pub name: String,
    /// `user@host` the connection is made to.
    pub ssh_host: String,
    /// Port sshd listens on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_port: Option<u16>,
    /// Private key the host authenticates with.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_identity_file: Option<String>,
    /// Directory the agent starts in on the remote side.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_directory: Option<String>,
}

impl From<&SandboxEndpoint> for SshConfig {
    fn from(endpoint: &SandboxEndpoint) -> Self {
        Self {
            id: endpoint.id.clone(),
            name: format!("cyber-sandbox {}", endpoint.id),
            ssh_host: endpoint.destination(),
            ssh_port: Some(endpoint.port),
            ssh_identity_file: Some(endpoint.identity_file.display().to_string()),
            start_directory: Some(endpoint.start_directory.display().to_string()),
        }
    }
}

/// Claude Code's settings file, edited in place.
#[derive(Debug, Clone)]
pub struct ClaudeSettings {
    path: PathBuf,
}

impl ClaudeSettings {
    /// Points at the settings file to edit.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Path being edited.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Adds `endpoint`, replacing any entry that already carries the same id.
    ///
    /// # Errors
    /// Fails when the settings cannot be read, are not a JSON object, or cannot be written.
    pub async fn register(&self, endpoint: &SandboxEndpoint) -> Result<(), AgentError> {
        let mut settings = self.read().await?;
        let mut configs = self.configs_of(&settings)?;
        configs.retain(|config| config.id != endpoint.id);
        configs.push(SshConfig::from(endpoint));
        self.store(&mut settings, configs)?;
        self.write(&settings).await
    }

    /// Removes the entry carrying `id`, leaving the file untouched when there is none.
    ///
    /// # Errors
    /// Fails when the settings cannot be read, are not a JSON object, or cannot be written.
    pub async fn unregister(&self, id: &str) -> Result<(), AgentError> {
        let mut settings = self.read().await?;
        let mut configs = self.configs_of(&settings)?;
        let before = configs.len();
        configs.retain(|config| config.id != id);
        if configs.len() == before {
            return Ok(());
        }
        self.store(&mut settings, configs)?;
        self.write(&settings).await
    }

    async fn read(&self) -> Result<Map<String, Value>, AgentError> {
        let text = match fs::read_to_string(&self.path).await {
            Ok(text) => text,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Map::new());
            }
            Err(source) => {
                return Err(AgentError::Io {
                    path: self.path.clone(),
                    source,
                });
            }
        };
        if text.trim().is_empty() {
            return Ok(Map::new());
        }
        let value: Value = serde_json::from_str(&text).map_err(|source| AgentError::Json {
            path: self.path.clone(),
            source,
        })?;
        match value {
            Value::Object(settings) => Ok(settings),
            _ => Err(AgentError::NotAnObject {
                path: self.path.clone(),
            }),
        }
    }

    fn configs_of(&self, settings: &Map<String, Value>) -> Result<Vec<SshConfig>, AgentError> {
        let Some(value) = settings.get(SSH_CONFIGS) else {
            return Ok(Vec::new());
        };
        serde_json::from_value(value.clone()).map_err(|source| AgentError::Json {
            path: self.path.clone(),
            source,
        })
    }

    fn store(
        &self,
        settings: &mut Map<String, Value>,
        configs: Vec<SshConfig>,
    ) -> Result<(), AgentError> {
        let value = serde_json::to_value(configs).map_err(|source| AgentError::Json {
            path: self.path.clone(),
            source,
        })?;
        settings.insert(SSH_CONFIGS.to_owned(), value);
        Ok(())
    }

    async fn write(&self, settings: &Map<String, Value>) -> Result<(), AgentError> {
        let mut text =
            serde_json::to_string_pretty(settings).map_err(|source| AgentError::Json {
                path: self.path.clone(),
                source,
            })?;
        text.push('\n');
        write_file(&self.path, &text).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn endpoint(id: &str) -> SandboxEndpoint {
        SandboxEndpoint {
            id: id.to_owned(),
            user: "researcher".to_owned(),
            host: "192.168.64.7".to_owned(),
            port: 22,
            identity_file: PathBuf::from("/keys/id_ed25519"),
            known_hosts: PathBuf::from("/keys/known_hosts"),
            start_directory: PathBuf::from("/work"),
        }
    }

    #[tokio::test]
    async fn registering_preserves_unrelated_settings_and_replaces_by_id() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("settings.json");
        tokio::fs::write(&path, "{\"model\":\"opus\",\"sshConfigs\":[]}")
            .await
            .unwrap();
        let settings = ClaudeSettings::new(path.clone());

        settings.register(&endpoint("alpha")).await.unwrap();
        settings.register(&endpoint("alpha")).await.unwrap();
        settings.register(&endpoint("beta")).await.unwrap();

        let stored: Value =
            serde_json::from_str(&tokio::fs::read_to_string(&path).await.unwrap()).unwrap();
        assert_eq!(stored["model"], "opus");
        let configs = stored[SSH_CONFIGS].as_array().unwrap();
        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0]["id"], "alpha");
        assert_eq!(configs[0]["sshHost"], "researcher@192.168.64.7");
        assert_eq!(configs[0]["startDirectory"], "/work");
    }

    #[tokio::test]
    async fn unregistering_an_absent_id_leaves_the_file_alone() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("settings.json");
        let original = "{\"model\":\"opus\"}";
        tokio::fs::write(&path, original).await.unwrap();

        ClaudeSettings::new(path.clone())
            .unregister("absent")
            .await
            .unwrap();

        assert_eq!(tokio::fs::read_to_string(&path).await.unwrap(), original);
    }

    #[tokio::test]
    async fn a_missing_settings_file_is_created_with_only_the_new_entry() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("nested").join("settings.json");
        ClaudeSettings::new(path.clone())
            .register(&endpoint("alpha"))
            .await
            .unwrap();

        let stored: Value =
            serde_json::from_str(&tokio::fs::read_to_string(&path).await.unwrap()).unwrap();
        assert_eq!(stored[SSH_CONFIGS].as_array().unwrap().len(), 1);
    }
}
