use std::{net::IpAddr, num::NonZeroU32, path::PathBuf};

use clap::{Args, Parser, Subcommand};
use cyber_sandbox_image::ToolProfile;
use cyber_sandbox_runtime::{Arch, ImageReference};

/// Default tag the sandbox image is built under and started from.
pub const DEFAULT_IMAGE: &str = "localhost/cyber-sandbox:latest";

/// Kali image the sandbox derives from by default.
pub const DEFAULT_BASE_IMAGE: &str = "docker.io/kalilinux/kali-rolling:latest";

/// Resolver the in-sandbox gateway forwards DNS to by default.
///
/// The gateway dials it directly, so it is the one destination the sandbox reaches
/// without being redirected — the sandbox itself still cannot speak to it.
pub const DEFAULT_RESOLVER: &str = "1.1.1.1";

/// cyber-sandbox's command line.
#[derive(Debug, Parser)]
#[command(name = "cyber-sandbox", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// The top-level commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Reports whether the host can run sandboxes, and repairs what it can.
    Doctor(Doctor),
    /// Builds the sandbox image.
    Image {
        #[command(subcommand)]
        command: ImageCommand,
    },
    /// Starts a sandbox and registers it with both agents.
    Up(Up),
    /// Opens a shell, or runs a command, inside a running sandbox.
    Ssh(Ssh),
    /// Stops a sandbox without destroying it.
    Down(Target),
    /// Lists the sandboxes the host knows about.
    Ls,
    /// Destroys a sandbox and removes it from both agents.
    Rm(Target),
    /// Reads the sandbox's network audit trail.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
}

/// Arguments of `doctor`.
#[derive(Debug, Args)]
pub struct Doctor {
    /// Start the runtime's system services when they are not already running.
    #[arg(long)]
    pub fix: bool,
}

/// The `image` subcommands.
#[derive(Debug, Subcommand)]
pub enum ImageCommand {
    /// Renders the build context and builds the sandbox image.
    Build(ImageBuildArgs),
}

/// Arguments of `image build`.
#[derive(Debug, Args)]
pub struct ImageBuildArgs {
    /// Tag to build the image under.
    #[arg(long, default_value = DEFAULT_IMAGE)]
    pub tag: ImageReference,
    /// Kali image to derive from.
    #[arg(long, default_value = DEFAULT_BASE_IMAGE)]
    pub base_image: String,
    /// Guest architecture the image is built for.
    #[arg(long, default_value = "arm64")]
    pub arch: Arch,
    /// How much of the Kali toolchain to install.
    #[arg(long, default_value = "core")]
    pub profile: ToolProfile,
    /// Workspace holding the gateway sources the image compiles.
    #[arg(long, default_value = ".")]
    pub workspace: PathBuf,
}

/// Arguments of `up`.
#[derive(Debug, Args)]
pub struct Up {
    /// Name of the sandbox, which is also its container name and agent entry id.
    pub id: String,
    /// Image to start, built on demand when the runtime does not hold it.
    #[arg(long, default_value = DEFAULT_IMAGE)]
    pub image: ImageReference,
    /// Guest architecture. `amd64` runs an `x86_64` root filesystem under Rosetta.
    #[arg(long, default_value = "arm64")]
    pub arch: Arch,
    /// Virtual CPUs the sandbox is given. Defaults to half of what the host can spare.
    #[arg(long)]
    pub cpus: Option<NonZeroU32>,
    /// Memory in mebibytes. Defaults to half of what the host can spare.
    ///
    /// Whatever is asked for is checked against the host first: a sandbox is never given
    /// so much that macOS is left without its own share.
    #[arg(long)]
    pub memory_mib: Option<NonZeroU32>,
    /// Host directory exposed read-only as the sample source.
    #[arg(long)]
    pub samples: Option<PathBuf>,
    /// Resolver the gateway forwards the sandbox's DNS questions to.
    #[arg(long, default_value = DEFAULT_RESOLVER)]
    pub resolver: IpAddr,
    /// Toolchain profile used if the image has to be built first.
    #[arg(long, default_value = "core")]
    pub profile: ToolProfile,
    /// Workspace used if the image has to be built first.
    #[arg(long, default_value = ".")]
    pub workspace: PathBuf,
}

/// A command that acts on one existing sandbox.
#[derive(Debug, Args)]
pub struct Target {
    /// Name of the sandbox.
    pub id: String,
}

/// Arguments of `ssh`.
#[derive(Debug, Args)]
pub struct Ssh {
    /// Name of the sandbox.
    pub id: String,
    /// Command to run instead of an interactive shell.
    #[arg(trailing_var_arg = true)]
    pub command: Vec<String>,
}

/// The `audit` subcommands.
#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// Prints the tail of the audit trail, optionally following it.
    Tail(AuditTail),
    /// Copies the whole audit trail out of the sandbox.
    Export(AuditExport),
}

/// Arguments of `audit tail`.
#[derive(Debug, Args)]
pub struct AuditTail {
    /// Name of the sandbox.
    pub id: String,
    /// Number of trailing records to print before following.
    #[arg(long, short = 'n', default_value = "20")]
    pub lines: u32,
    /// Keep printing records as the gateway writes them.
    #[arg(long, short = 'f')]
    pub follow: bool,
}

/// Arguments of `audit export`.
#[derive(Debug, Args)]
pub struct AuditExport {
    /// Name of the sandbox.
    pub id: String,
    /// File to write the trail to. Defaults to standard output.
    #[arg(long, short = 'o')]
    pub output: Option<PathBuf>,
}
