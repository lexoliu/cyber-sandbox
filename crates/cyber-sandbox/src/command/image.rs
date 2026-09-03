use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use cyber_sandbox_image::{BuildContext, ToolProfile};
use cyber_sandbox_runtime::{Arch, Build, ImageReference};

use crate::{cli, host::Host};

/// Bytes in a gibibyte, for reporting free space.
const GIB: u64 = 1024 * 1024 * 1024;

/// Crate whose presence proves the given directory really is the cyber-sandbox workspace.
const GATEWAY_CRATE: &str = "crates/cyber-sandbox-gateway/Cargo.toml";

/// Builds the sandbox image from `arguments`.
///
/// # Errors
/// Fails when the workspace does not hold the gateway sources, when the build context
/// cannot be staged, or when the builder exits non-zero.
pub async fn build(host: &Host, arguments: &cli::ImageBuildArgs) -> Result<()> {
    run(
        host,
        &arguments.workspace,
        arguments.tag.clone(),
        &arguments.base_image,
        arguments.arch,
        arguments.profile,
    )
    .await
}

/// Builds `tag` from `workspace`, which is what both `image build` and an `up` against a
/// missing image do.
///
/// # Errors
/// Fails when the workspace does not hold the gateway sources, when the build context
/// cannot be staged, or when the builder exits non-zero.
pub async fn run(
    host: &Host,
    workspace: &Path,
    tag: ImageReference,
    base_image: &str,
    arch: Arch,
    profile: ToolProfile,
) -> Result<()> {
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
            "{} does not hold {GATEWAY_CRATE}; point `--workspace` at a cyber-sandbox checkout, \
             because the image compiles the audit gateway from source",
            workspace.display()
        );
    }
    Ok(workspace)
}
