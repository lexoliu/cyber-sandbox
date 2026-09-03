use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use cyber_sandbox_agents::{AgentIntegration, key_directory};
use cyber_sandbox_image::SandboxLayout;
use cyber_sandbox_runtime::{AppleContainer, ContainerName};

use crate::record::SandboxRecord;

/// Directory under the user's home holding everything cyber-sandbox owns.
const STATE_DIRECTORY: &str = ".cyber-sandbox";

/// Everything a command needs to reach both the runtime and the host's own state.
///
/// Constructed once per invocation so that the runtime binary, the layout the image was
/// built from and the state directory cannot disagree between commands.
#[derive(Debug, Clone)]
pub struct Host {
    home: PathBuf,
    state: PathBuf,
    runtime: AppleContainer,
    layout: SandboxLayout,
}

impl Host {
    /// Locates the runtime and the host's state directory.
    ///
    /// # Errors
    /// Fails when the home directory is unknown or `container` is not installed.
    pub fn discover() -> Result<Self> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .context("HOME is not set, so the host's configuration cannot be located")?;
        let runtime = AppleContainer::discover()?;
        Ok(Self {
            state: home.join(STATE_DIRECTORY),
            home,
            runtime,
            layout: SandboxLayout::default(),
        })
    }

    /// The `apple/container` driver.
    #[must_use]
    pub fn runtime(&self) -> &AppleContainer {
        &self.runtime
    }

    /// The layout the sandbox image was rendered from.
    #[must_use]
    pub fn layout(&self) -> &SandboxLayout {
        &self.layout
    }

    /// The host's agent configuration files.
    #[must_use]
    pub fn agents(&self) -> AgentIntegration {
        AgentIntegration::for_home(&self.home)
    }

    /// Directory holding the per-sandbox SSH identities.
    #[must_use]
    pub fn key_directory(&self) -> PathBuf {
        key_directory(&self.home)
    }

    /// Directory image build contexts are staged into.
    #[must_use]
    pub fn build_directory(&self) -> PathBuf {
        self.state.join("build")
    }

    /// Path of the record describing `id`.
    #[must_use]
    pub fn record_path(&self, id: &str) -> PathBuf {
        self.state.join("sandboxes").join(format!("{id}.json"))
    }

    /// Reads the record for `id`.
    ///
    /// # Errors
    /// Fails when no such sandbox has been started, or the record cannot be read.
    pub async fn record(&self, id: &str) -> Result<SandboxRecord> {
        let path = self.record_path(id);
        let text = match tokio::fs::read_to_string(&path).await {
            Ok(text) => text,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                bail!("no sandbox named `{id}`; start one with `cyber-sandbox up {id}`")
            }
            Err(source) => {
                return Err(source).with_context(|| format!("reading {}", path.display()));
            }
        };
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    /// Every sandbox the host has started, ordered by id.
    ///
    /// # Errors
    /// Fails when the state directory cannot be read or holds an unreadable record.
    pub async fn records(&self) -> Result<Vec<SandboxRecord>> {
        let directory = self.state.join("sandboxes");
        let mut entries = match tokio::fs::read_dir(&directory).await {
            Ok(entries) => entries,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => {
                return Err(source).with_context(|| format!("reading {}", directory.display()));
            }
        };
        let mut records = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .with_context(|| format!("reading {}", directory.display()))?
        {
            let path = entry.path();
            if path.extension().is_none_or(|extension| extension != "json") {
                continue;
            }
            let text = tokio::fs::read_to_string(&path)
                .await
                .with_context(|| format!("reading {}", path.display()))?;
            records.push(
                serde_json::from_str::<SandboxRecord>(&text)
                    .with_context(|| format!("parsing {}", path.display()))?,
            );
        }
        records.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(records)
    }

    /// Writes the record for a sandbox that has just started.
    ///
    /// # Errors
    /// Fails when the state directory cannot be created or written.
    pub async fn store(&self, record: &SandboxRecord) -> Result<()> {
        let path = self.record_path(&record.id);
        create_parent(&path).await?;
        let mut text =
            serde_json::to_string_pretty(record).context("encoding the sandbox record")?;
        text.push('\n');
        tokio::fs::write(&path, text)
            .await
            .with_context(|| format!("writing {}", path.display()))
    }

    /// Deletes the record for `id`, tolerating one that is already gone.
    ///
    /// # Errors
    /// Fails when the record exists but cannot be removed.
    pub async fn forget(&self, id: &str) -> Result<()> {
        let path = self.record_path(id);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(source).with_context(|| format!("removing {}", path.display())),
        }
    }

    /// The container name a sandbox id maps to.
    ///
    /// # Errors
    /// Fails when the id is not a name the runtime accepts.
    pub fn container_name(id: &str) -> Result<ContainerName> {
        ContainerName::new(id).map_err(Into::into)
    }
}

async fn create_parent(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    tokio::fs::create_dir_all(parent)
        .await
        .with_context(|| format!("creating {}", parent.display()))
}
