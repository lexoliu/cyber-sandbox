//! Codex's `environments.toml` entry for a sandbox.
//!
//! Codex has no `ssh` subcommand. Its equivalent is a configured environment whose
//! transport is a stdio command: the host's app-server — which holds the credential —
//! spawns `ssh` and speaks the exec-server protocol over its standard streams. The
//! sandbox therefore runs only `codex exec-server --listen stdio`, and never authenticates
//! to anything.
//!
//! The schema is upstream's `EnvironmentsToml`: `default`, `include_local`, and an
//! `[[environments]]` array whose entries set exactly one of `url` or `program`. `args`,
//! `env` and `cwd` are only accepted alongside `program`, and `cwd` is the *host's*
//! working directory for the spawned `ssh`, not a path inside the sandbox — the sandbox's
//! start directory is part of the remote command instead.

use std::path::{Path, PathBuf};

use toml_edit::{Array, ArrayOfTables, DocumentMut, Item, Table, value};

use crate::{endpoint::SandboxEndpoint, error::AgentError, write_file};

/// Top-level key holding the array of configured environments.
const ENVIRONMENTS: &str = "environments";

/// The remote program the sandbox runs, speaking the exec-server protocol over stdio.
///
/// Nothing more is needed to make the server die with the session: in `stdio` mode the
/// pipes *are* the transport, so sshd closing them at disconnect is end of input and the
/// server exits. `--exit-on-stdin-close` is for the `--remote` mode, where the transport
/// is a socket and the pipe is only a lifetime signal — codex 0.153.0 makes
/// `--environment-id` and `--remote` required as soon as it is passed, so adding it here
/// breaks the connection outright.
const REMOTE_COMMAND: &[&str] = &["codex", "exec-server", "--listen", "stdio"];

/// Codex's environments file, edited in place.
#[derive(Debug, Clone)]
pub struct CodexEnvironments {
    path: PathBuf,
}

impl CodexEnvironments {
    /// Points at the environments file to edit.
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
    /// Fails when the file cannot be read, is not valid TOML, or cannot be written.
    pub async fn register(&self, endpoint: &SandboxEndpoint) -> Result<(), AgentError> {
        let mut document = self.read().await?;
        let environments = self.environments_of(&mut document)?;
        environments.retain(|table| Self::id_of(table) != Some(endpoint.id.as_str()));
        environments.push(Self::entry(endpoint));
        self.write(&document).await
    }

    /// Removes the entry carrying `id`, leaving the file untouched when there is none.
    ///
    /// # Errors
    /// Fails when the file cannot be read, is not valid TOML, or cannot be written.
    pub async fn unregister(&self, id: &str) -> Result<(), AgentError> {
        let mut document = self.read().await?;
        let environments = self.environments_of(&mut document)?;
        let before = environments.len();
        environments.retain(|table| Self::id_of(table) != Some(id));
        if environments.len() == before {
            return Ok(());
        }
        self.write(&document).await
    }

    /// The remote command line, which changes into the sandbox's start directory before
    /// replacing itself with the exec-server.
    fn remote_command(endpoint: &SandboxEndpoint) -> String {
        format!(
            "cd {} && exec {}",
            endpoint.start_directory.display(),
            REMOTE_COMMAND.join(" ")
        )
    }

    fn entry(endpoint: &SandboxEndpoint) -> Table {
        let mut table = Table::new();
        table["id"] = value(endpoint.id.as_str());
        table["program"] = value("ssh");
        let mut args = Array::new();
        for argument in endpoint.ssh_arguments() {
            args.push(argument);
        }
        args.push(Self::remote_command(endpoint));
        table["args"] = value(args);
        table
    }

    /// The `[[environments]]` array, created when the file does not have one yet.
    ///
    /// A present `environments` key holding anything else is somebody's hand-written
    /// configuration in a shape this tool does not understand, so it is refused rather
    /// than overwritten.
    fn environments_of<'a>(
        &self,
        document: &'a mut DocumentMut,
    ) -> Result<&'a mut ArrayOfTables, AgentError> {
        let entry = document
            .entry(ENVIRONMENTS)
            .or_insert_with(|| Item::ArrayOfTables(ArrayOfTables::new()));
        entry
            .as_array_of_tables_mut()
            .ok_or_else(|| AgentError::UnexpectedShape {
                path: self.path.clone(),
                key: ENVIRONMENTS,
            })
    }

    fn id_of(table: &Table) -> Option<&str> {
        table.get("id")?.as_str()
    }

    async fn read(&self) -> Result<DocumentMut, AgentError> {
        let text = match tokio::fs::read_to_string(&self.path).await {
            Ok(text) => text,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(DocumentMut::new());
            }
            Err(source) => {
                return Err(AgentError::Io {
                    path: self.path.clone(),
                    source,
                });
            }
        };
        text.parse().map_err(|source| AgentError::Toml {
            path: self.path.clone(),
            source,
        })
    }

    async fn write(&self, document: &DocumentMut) -> Result<(), AgentError> {
        write_file(&self.path, &document.to_string()).await
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
            port: 2222,
            identity_file: PathBuf::from("/keys/id_ed25519"),
            start_directory: PathBuf::from("/work"),
        }
    }

    #[tokio::test]
    async fn registering_replaces_by_id_and_keeps_hand_written_entries() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("environments.toml");
        tokio::fs::write(
            &path,
            "default = \"laptop\"\n\n[[environments]]\nid = \"laptop\"\nurl = \"ws://127.0.0.1:1234\"\n",
        )
        .await
        .unwrap();
        let environments = CodexEnvironments::new(path.clone());

        environments.register(&endpoint("alpha")).await.unwrap();
        environments.register(&endpoint("alpha")).await.unwrap();

        let stored = tokio::fs::read_to_string(&path).await.unwrap();
        let document: DocumentMut = stored.parse().unwrap();
        assert_eq!(document["default"].as_str(), Some("laptop"));
        let entries = document[ENVIRONMENTS].as_array_of_tables().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries.get(1).unwrap()["id"].as_str(), Some("alpha"));
        assert_eq!(entries.get(1).unwrap()["program"].as_str(), Some("ssh"));
    }

    #[tokio::test]
    async fn the_entry_never_sets_both_url_and_program() {
        let table = CodexEnvironments::entry(&endpoint("alpha"));
        assert!(table.get("url").is_none());
        assert_eq!(table["program"].as_str(), Some("ssh"));
    }

    #[tokio::test]
    async fn the_remote_command_starts_the_exec_server_in_the_start_directory() {
        let table = CodexEnvironments::entry(&endpoint("alpha"));
        let args: Vec<&str> = table["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|argument| argument.as_str().unwrap())
            .collect();
        assert_eq!(args.first(), Some(&"-p"));
        assert!(args.contains(&"ForwardAgent=no"));
        assert_eq!(
            args.last(),
            Some(&"cd /work && exec codex exec-server --listen stdio")
        );
    }

    #[tokio::test]
    async fn unregistering_an_absent_id_leaves_the_file_alone() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("environments.toml");
        let original = "default = \"laptop\"\n";
        tokio::fs::write(&path, original).await.unwrap();

        CodexEnvironments::new(path.clone())
            .unregister("absent")
            .await
            .unwrap();

        assert_eq!(tokio::fs::read_to_string(&path).await.unwrap(), original);
    }
}
