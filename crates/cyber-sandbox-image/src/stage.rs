use std::path::{Path, PathBuf};

use cyber_sandbox_runtime::{Arch, ImageBuild, ImageReference, RuntimeError};

use crate::{layout::SandboxLayout, profile::ToolProfile, render::RenderedImage};

/// Files the builder needs from the workspace in order to compile the gateway.
const WORKSPACE_FILES: &[&str] = &["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"];

/// Errors raised while materialising an image build context.
#[derive(Debug, thiserror::Error)]
pub enum StageError {
    /// A template could not be rendered.
    #[error("failed to render the image templates")]
    Render(#[from] askama::Error),
    /// The staging directory could not be written.
    #[error("failed to stage the build context at {path}")]
    Io {
        /// Path being written when the failure occurred.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },
    /// The image reference the caller asked for is not valid.
    #[error("the image tag is not a valid reference")]
    Tag(#[from] RuntimeError),
}

/// A staged directory holding everything `container build` needs.
#[derive(Debug)]
pub struct BuildContext {
    directory: PathBuf,
    tag: ImageReference,
    arch: Arch,
}

impl BuildContext {
    /// Renders the image and copies the gateway sources into `directory`.
    ///
    /// The staging directory is emptied first, so a stale Dockerfile from an earlier
    /// layout can never be handed to the builder.
    ///
    /// # Errors
    /// Fails when a template cannot be rendered, when the workspace sources cannot be
    /// read, or when the staging directory cannot be written.
    pub async fn stage(
        directory: impl Into<PathBuf>,
        workspace_root: &Path,
        tag: ImageReference,
        base_image: &str,
        arch: Arch,
        profile: ToolProfile,
        layout: &SandboxLayout,
    ) -> Result<Self, StageError> {
        let directory = directory.into();
        let rendered = RenderedImage::render(base_image, arch, profile, layout)?;

        remove_dir_all_if_present(&directory).await?;
        create_dir_all(&directory).await?;

        for file in WORKSPACE_FILES {
            copy_file(&workspace_root.join(file), &directory.join(file)).await?;
        }
        copy_tree(&workspace_root.join("crates"), &directory.join("crates")).await?;

        write_file(&directory.join("Dockerfile"), &rendered.dockerfile).await?;
        write_file(&directory.join("entrypoint.sh"), &rendered.entrypoint).await?;
        write_file(&directory.join("egress-policy.sh"), &rendered.egress_policy).await?;
        write_file(&directory.join("sshd_config"), &rendered.sshd_config).await?;
        write_file(&directory.join("claude.json"), &rendered.claude_config).await?;
        write_file(
            &directory.join("claude-settings.json"),
            &rendered.claude_settings,
        )
        .await?;

        Ok(Self {
            directory,
            tag,
            arch,
        })
    }

    /// Directory the context was staged into.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// The build request to hand to the runtime.
    #[must_use]
    pub fn build_request(&self) -> ImageBuild {
        ImageBuild {
            tag: self.tag.clone(),
            context: self.directory.clone(),
            dockerfile: self.directory.join("Dockerfile"),
            arch: self.arch,
            build_args: Vec::new(),
        }
    }
}

async fn remove_dir_all_if_present(path: &Path) -> Result<(), StageError> {
    match tokio::fs::remove_dir_all(path).await {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(StageError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

async fn create_dir_all(path: &Path) -> Result<(), StageError> {
    tokio::fs::create_dir_all(path)
        .await
        .map_err(|source| StageError::Io {
            path: path.to_path_buf(),
            source,
        })
}

async fn copy_file(from: &Path, to: &Path) -> Result<(), StageError> {
    tokio::fs::copy(from, to)
        .await
        .map(drop)
        .map_err(|source| StageError::Io {
            path: from.to_path_buf(),
            source,
        })
}

async fn write_file(path: &Path, contents: &str) -> Result<(), StageError> {
    tokio::fs::write(path, contents)
        .await
        .map_err(|source| StageError::Io {
            path: path.to_path_buf(),
            source,
        })
}

async fn copy_tree(from: &Path, to: &Path) -> Result<(), StageError> {
    create_dir_all(to).await?;
    let mut pending = vec![(from.to_path_buf(), to.to_path_buf())];
    while let Some((source_dir, target_dir)) = pending.pop() {
        let mut entries =
            tokio::fs::read_dir(&source_dir)
                .await
                .map_err(|source| StageError::Io {
                    path: source_dir.clone(),
                    source,
                })?;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|source| StageError::Io {
                path: source_dir.clone(),
                source,
            })?
        {
            let source_path = entry.path();
            let target_path = target_dir.join(entry.file_name());
            let file_type = entry.file_type().await.map_err(|source| StageError::Io {
                path: source_path.clone(),
                source,
            })?;
            if file_type.is_dir() {
                create_dir_all(&target_path).await?;
                pending.push((source_path, target_path));
            } else {
                copy_file(&source_path, &target_path).await?;
            }
        }
    }
    Ok(())
}
