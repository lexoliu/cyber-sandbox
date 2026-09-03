//! cyber-sandbox: isolated, fully audited security-research environments on macOS.
//!
//! Every sandbox is one lightweight virtual machine. The research agents keep their
//! credentials on the host and reach it over SSH, so nothing inside the sandbox holds a
//! token; every packet the sandbox sends is either audited by the in-guest gateway or
//! refused by the packet filter.

mod cli;
mod command;
mod host;
mod keys;
mod record;

use anyhow::Result;
use clap::Parser as _;
use tracing_subscriber::EnvFilter;

use crate::{cli::Cli, host::Host};

/// Exit status returned when `doctor` finds the host unable to run sandboxes.
const NOT_READY: i32 = 1;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("CYBER_SANDBOX_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    let arguments = Cli::parse();
    let host = Host::discover()?;

    match &arguments.command {
        cli::Command::Doctor(doctor) => {
            if !command::doctor::run(&host, doctor).await? {
                std::process::exit(NOT_READY);
            }
            Ok(())
        }
        cli::Command::Image { command } => match command {
            cli::ImageCommand::Build(build) => command::image::build(&host, build).await,
        },
        cli::Command::Up(up) => command::lifecycle::up(&host, up).await,
        cli::Command::Ssh(ssh) => command::ssh::run(&host, ssh).await,
        cli::Command::Down(target) => command::lifecycle::down(&host, target).await,
        cli::Command::Ls => command::lifecycle::ls(&host).await,
        cli::Command::Rm(target) => command::lifecycle::rm(&host, target).await,
        cli::Command::Audit { command } => match command {
            cli::AuditCommand::Tail(tail) => command::audit::tail(&host, tail).await,
            cli::AuditCommand::Export(export) => command::audit::export(&host, export).await,
        },
    }
}
