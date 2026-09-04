//! Codex's `config.toml`, so far as a session needs to touch it.
//!
//! Codex asks, the first time it is opened in a directory, whether the researcher trusts
//! its contents, and remembers the answer under `[projects."<path>"]`. The directory a
//! session hands it is one cyber-sandbox made for that session and nothing else can
//! write to, so the question has no answer to discover — but it is asked once per
//! session, which is exactly the babysitting a session exists to remove.
//!
//! A command-line override does not answer it: the prompt is driven by what is on disk.
//! So the trust is written before Codex starts and taken out again when it exits, the
//! same way the session's environment entry is, and the researcher's own file is left
//! holding what it held.

use std::path::{Path, PathBuf};

use toml_edit::{Item, Table, value};

use crate::{error::AgentError, toml_file::TomlFile};

/// Table holding what Codex remembers about each directory it has been opened in.
const PROJECTS: &str = "projects";

/// Key naming how far a directory is trusted, and the only value that skips the prompt.
const TRUST_LEVEL: &str = "trust_level";
const TRUSTED: &str = "trusted";

/// Codex's configuration file, edited in place.
#[derive(Debug, Clone)]
pub struct CodexConfig {
    file: TomlFile,
}

impl CodexConfig {
    /// Points at the configuration file to edit.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self {
            file: TomlFile::new(path),
        }
    }

    /// Path being edited.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.file.path()
    }

    /// Records that `directory` is trusted, so Codex opens in it without asking.
    ///
    /// # Errors
    /// Fails when the file cannot be read, is not valid TOML, or cannot be written.
    pub async fn trust(&self, directory: &Path) -> Result<(), AgentError> {
        let mut document = self.file.read().await?;
        let projects = self.projects_of(&mut document)?;
        // A table of its own rather than an inline value: an inline one would force a
        // `[projects]` header into a file whose own entries hang off the bare name, which
        // is a change to the researcher's file that outlives the session.
        let mut entry = Table::new();
        entry[TRUST_LEVEL] = value(TRUSTED);
        projects.insert(&directory.display().to_string(), Item::Table(entry));
        self.file.write(&document).await
    }

    /// Takes back the trust recorded for `directory`, leaving the file alone when there
    /// is none.
    ///
    /// # Errors
    /// Fails when the file cannot be read, is not valid TOML, or cannot be written.
    pub async fn distrust(&self, directory: &Path) -> Result<(), AgentError> {
        let mut document = self.file.read().await?;
        let projects = self.projects_of(&mut document)?;
        if projects.remove(&directory.display().to_string()).is_none() {
            return Ok(());
        }
        if projects.is_empty() {
            document.remove(PROJECTS);
        }
        self.file.write(&document).await
    }

    /// The `[projects]` table, created — as a header the entries hang off rather than a
    /// table of its own — when the file does not have one yet.
    ///
    /// A `projects` key holding anything else is somebody's hand-written configuration in
    /// a shape this tool does not understand, so it is refused rather than overwritten.
    fn projects_of<'a>(
        &self,
        document: &'a mut toml_edit::DocumentMut,
    ) -> Result<&'a mut Table, AgentError> {
        let entry = document.entry(PROJECTS).or_insert_with(|| {
            let mut table = Table::new();
            table.set_implicit(true);
            Item::Table(table)
        });
        entry
            .as_table_mut()
            .ok_or_else(|| AgentError::UnexpectedShape {
                path: self.path().to_path_buf(),
                key: PROJECTS,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn stored(path: &Path) -> String {
        tokio::fs::read_to_string(path).await.unwrap()
    }

    #[tokio::test]
    async fn a_trusted_directory_is_recorded_where_codex_looks_for_it() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("config.toml");
        let config = CodexConfig::new(path.clone());

        config
            .trust(Path::new("/home/researcher/.cyber-sandbox/work/c0ffee"))
            .await
            .unwrap();

        assert_eq!(
            stored(&path).await,
            "[projects.\"/home/researcher/.cyber-sandbox/work/c0ffee\"]\n\
             trust_level = \"trusted\"\n"
        );
    }

    #[tokio::test]
    async fn the_researchers_own_configuration_comes_back_exactly_as_it_was() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("config.toml");
        let original = "model = \"gpt-5\"\n\n\
                        # the laptop\n\
                        [projects.\"/home/researcher/work\"]\n\
                        trust_level = \"trusted\"\n";
        tokio::fs::write(&path, original).await.unwrap();
        let config = CodexConfig::new(path.clone());
        let session = Path::new("/home/researcher/.cyber-sandbox/work/c0ffee");

        config.trust(session).await.unwrap();
        config.distrust(session).await.unwrap();

        assert_eq!(
            stored(&path).await,
            original,
            "a session that has closed must leave no trace in a file it does not own"
        );
    }

    #[tokio::test]
    async fn distrusting_a_directory_that_was_never_trusted_leaves_the_file_alone() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("config.toml");
        let original = "model = \"gpt-5\"\n";
        tokio::fs::write(&path, original).await.unwrap();

        CodexConfig::new(path.clone())
            .distrust(Path::new("/home/researcher/.cyber-sandbox/work/c0ffee"))
            .await
            .unwrap();

        assert_eq!(stored(&path).await, original);
    }
}
