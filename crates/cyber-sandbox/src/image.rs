//! Building the sandbox image, which nobody asks for directly.
//!
//! The image is an implementation detail of a session: it is built the first time a
//! session needs one for its architecture, and never again. There is no command for it,
//! because a researcher asking for an environment has no reason to know that one of the
//! steps is a Kali image with the audit gateway compiled into it.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use cyber_sandbox_image::BuildContext;
use cyber_sandbox_runtime::{Arch, Build};

use crate::{cli, host::Host};

/// Bytes in a gibibyte, for reporting free space.
const GIB: u64 = 1024 * 1024 * 1024;

/// Crate whose presence proves the given directory really is the cyber-sandbox workspace.
const GATEWAY_CRATE: &str = "crates/cyber-sandbox-gateway/Cargo.toml";

/// Builds the image a session of architecture `arch` starts from.
///
/// # Errors
/// Fails when the workspace does not hold the gateway sources, when the build context
/// cannot be staged, or when the builder exits non-zero.
pub async fn build(host: &Host, workspace: &Path, arch: Arch) -> Result<()> {
    let tag = cli::default_image(arch);
    let base_image = cli::DEFAULT_BASE_IMAGE;
    let profile = cli::DEFAULT_PROFILE;
    let workspace = resolve_workspace(workspace)?;
    let staging = host.build_directory().join(arch.as_str());

    tracing::info!(
        tag = %tag,
        arch = %arch,
        profile = %profile,
        workspace = %workspace.display(),
        "staging the sandbox image build context"
    );

    let context = BuildContext::stage(
        staging,
        &workspace,
        tag,
        base_image,
        arch,
        profile,
        host.layout(),
    )
    .await
    .context("staging the image build context")?;

    let budget = host.budget().await?;
    let reservation = budget.suggest::<Build>()?;
    tracing::info!(
        cpus = %reservation.cpus(),
        memory = %reservation.memory(),
        free_disk_gib = budget.free_disk() / GIB,
        "the host can carry this build"
    );

    host.runtime()
        .build(&context.build_request(), &reservation)
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
            "the sandbox image has not been built yet and {} does not hold {GATEWAY_CRATE}; \
             point `--workspace` at a cyber-sandbox checkout, because the image compiles \
             the audit gateway from source",
            workspace.display()
        );
    }
    Ok(workspace)
}
