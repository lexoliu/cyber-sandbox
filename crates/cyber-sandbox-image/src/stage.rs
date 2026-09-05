use std::path::{Path, PathBuf};

use cyber_sandbox_runtime::{Arch, ImageBuild, ImageReference, RuntimeError};

use crate::{
    digest::ContextDigest, layout::SandboxLayout, profile::ToolProfile, render::RenderedImage,
};

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
    /// The repository and digest did not form a reference the runtime accepts.
    #[error("the image tag is not a valid reference")]
    Tag(#[from] RuntimeError),
    /// The staged context could not be read back to be digested.
    #[error("failed to digest the build context at {path}")]
    Digest {
        /// Directory being digested.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },
}

/// A staged directory holding everything `container build` needs, and the digest that
/// names what it holds.
#[derive(Debug)]
pub struct BuildContext {
    directory: PathBuf,
    arch: Arch,
    digest: ContextDigest,
}

impl BuildContext {
    /// Renders the image and copies the gateway sources into `directory`, then digests
    /// the result.
    ///
    /// The staging directory is emptied first, so a stale Dockerfile from an earlier
    /// layout can never be handed to the builder — nor counted in the digest.
    ///
    /// # Errors
    /// Fails when a template cannot be rendered, when the workspace sources cannot be
    /// read, or when the staging directory cannot be written or read back.
    pub async fn stage(
        directory: impl Into<PathBuf>,
        workspace_root: &Path,
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
        write_file(&directory.join("sudoers"), &rendered.sudoers).await?;
        write_file(&directory.join("detonate.sh"), &rendered.detonate).await?;

        // Read back from disk rather than summed up while writing, so that what is
        // digested is exactly what the builder will be handed.
        let digested = directory.clone();
        let digest = tokio::task::spawn_blocking(move || ContextDigest::of_directory(&digested))
            .await
            .map_err(std::io::Error::other)
            .and_then(|digest| digest)
            .map_err(|source| StageError::Digest {
                path: directory.clone(),
                source,
            })?;

        Ok(Self {
            directory,
            arch,
            digest,
        })
    }

    /// Directory the context was staged into.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Digest of everything in the context.
    #[must_use]
    pub fn digest(&self) -> ContextDigest {
        self.digest
    }

    /// The reference an image built from this context is tagged with, under `repository`.
    ///
    /// The tag carries the architecture and the digest: the architecture because an
    /// `amd64` machine started from an `arm64` root filesystem cannot execute its own
    /// userspace, and the digest because an image built from other sources than the
    /// tool's is not the image the tool asked for, however recently it was built.
    ///
    /// # Errors
    /// Fails when `repository` does not form a reference the runtime accepts.
    pub fn reference(&self, repository: &str) -> Result<ImageReference, StageError> {
        Ok(ImageReference::new(format!(
            "{repository}:{}-{}",
            self.arch,
            self.digest.tag()
        ))?)
    }

    /// The build request to hand to the runtime, producing `tag`.
    #[must_use]
    pub fn build_request(&self, tag: ImageReference) -> ImageBuild {
        ImageBuild {
            tag,
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
