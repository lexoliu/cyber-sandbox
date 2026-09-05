//! Building the sandbox image, which nobody asks for directly.
//!
//! The image is an implementation detail of a session: it is built the first time a
//! session needs one, and again only when the sources it is built from have changed.
//! There is no command for it, because a researcher asking for an environment has no
//! reason to know that one of the steps is a Kali image with the audit gateway compiled
//! into it.
//!
//! The image is named for the digest of its build context, so the question "does the
//! runtime hold the image this tool would build?" is answered by looking the name up
//! rather than by trusting that whatever was built last is still right. An upgraded tool
//! stages a different context, names a different image, and builds it; an unchanged one
//! finds its image already there.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use cyber_sandbox_image::BuildContext;
use cyber_sandbox_runtime::{Arch, Build, ImageReference};

use crate::{cli, host::Host};

/// Bytes in a gibibyte, for reporting free space.
const GIB: u64 = 1024 * 1024 * 1024;

/// Crate whose presence proves the given directory really is the cyber-sandbox workspace.
const GATEWAY_CRATE: &str = "crates/cyber-sandbox-gateway/Cargo.toml";

/// A build context staged from the workspace, and the name of the image it produces.
#[derive(Debug)]
pub struct Staged {
    context: BuildContext,
    tag: ImageReference,
}

impl Staged {
    /// The image a session of this architecture starts from, whether or not it has been
    /// built yet.
    #[must_use]
    pub fn tag(&self) -> &ImageReference {
        &self.tag
    }
}

/// Stages the build context for architecture `arch` and names the image it describes.
///
/// Cheap next to a build — a render and a copy of the sources — and done for every new
/// session, because the name is the only way to know whether the runtime already holds
/// the image the tool would build.
///
/// # Errors
/// Fails when the workspace does not hold the gateway sources or when the build context
/// cannot be staged.
pub async fn stage(host: &Host, workspace: &Path, arch: Arch) -> Result<Staged> {
    let workspace = resolve_workspace(workspace)?;
    let staging = host.build_directory().join(arch.as_str());

    tracing::debug!(
        arch = %arch,
        profile = %cli::DEFAULT_PROFILE,
        workspace = %workspace.display(),
        "staging the sandbox image build context"
    );

    let context = BuildContext::stage(
        staging,
        &workspace,
        cli::DEFAULT_BASE_IMAGE,
        arch,
        cli::DEFAULT_PROFILE,
        host.layout(),
    )
    .await
    .context("staging the image build context")?;
    let tag = context
        .reference(cli::IMAGE_REPOSITORY)
        .context("naming the sandbox image")?;
    Ok(Staged { context, tag })
}

/// Makes sure the runtime holds the image `staged` names, building it if it does not.
///
/// # Errors
/// Fails when the runtime cannot be asked, when the host cannot carry a build, or when
/// the builder exits non-zero.
pub async fn ensure(host: &Host, staged: &Staged) -> Result<()> {
    if host.runtime().image_exists(&staged.tag).await? {
        tracing::debug!(image = %staged.tag, "the sandbox image is already built");
        return Ok(());
    }
    tracing::info!(
        image = %staged.tag,
        "building the sandbox image, because none was built from these sources"
    );

    let budget = host.budget().await?;
    let reservation = budget.suggest::<Build>()?;
    tracing::info!(
        cpus = %reservation.cpus(),
        memory = %reservation.memory(),
        free_disk_gib = budget.free_disk() / GIB,
        "the host can carry this build"
    );

    host.runtime()
        .build(
            &staged.context.build_request(staged.tag.clone()),
            &reservation,
        )
        .await
        .context("building the sandbox image")
}

/// Checks that `workspace` is the cyber-sandbox workspace, since the image compiles the
/// gateway from it.
///
/// The check is explicit rather than implicit because the builder's own error for a
/// missing crate is a wall of Cargo output that says nothing about the real cause.
fn resolve_workspace(workspace: &Path) -> Result<PathBuf> {
    let workspace = workspace
        .canonicalize()
        .with_context(|| format!("resolving the workspace {}", workspace.display()))?;
    if !workspace.join(GATEWAY_CRATE).is_file() {
        bail!(
            "{} does not hold {GATEWAY_CRATE}; point `--workspace` at a cyber-sandbox \
             checkout. A new session's image is compiled from those sources and named for \
             them, which is how a session always gets the image this version of the tool \
             describes",
            workspace.display()
        );
    }
    Ok(workspace)
}
