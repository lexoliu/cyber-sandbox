//! Runs Claude Code inside a session on a credential the host keeps lending it.
//!
//! Claude Code will take its credential from a file when told the host manages one, but
//! it does not take the file's word for it: the file names a process, and the credential
//! counts only while that process is alive and was started when the file says it was.
//! This program is that process. It fetches the current access token over a socket the
//! host forwarded in, writes the file, starts Claude Code, and keeps fetching for as long
//! as Claude Code runs — so a token that is renewed on the host reaches the session
//! without the session ever holding what renews it.
//!
//! It also means the loan ends when the session's Claude Code does. The file goes on the
//! way out, and even if it did not, nothing else could read it: the process it names is
//! gone, and the next process to be given that pid started at a different moment.

use std::{
    os::unix::process::ExitStatusExt as _,
    path::{Path, PathBuf},
    process::ExitStatus,
    time::Duration,
};

use anyhow::{Context as _, Result};
use clap::Parser;
use cyber_sandbox_creds::{Bearer, Credentials};
use jiff::Timestamp;
use tokio::{
    net::UnixStream,
    process::{Child, Command},
    signal::unix::{SignalKind, signal},
};

/// How often the token is fetched again.
///
/// The host renews its login well before the token it lends stops being accepted, and
/// this only has to notice within that margin. Fetching is a round trip over a socket
/// that is already open, so it is cheap enough to do far more often than needed and let
/// the margin be generous.
const REFRESH: Duration = Duration::from_secs(300);

/// The program Claude Code is started as.
const CLAUDE: &str = "claude";

/// Claude Code's own flag for picking up the conversation it last had here.
const CONTINUE: &str = "--continue";

/// Where Claude Code keeps its conversations, under the account's home directory.
const TRANSCRIPTS: &str = ".claude/projects";

/// Extension of one conversation's transcript.
const TRANSCRIPT: &str = "jsonl";

#[derive(Debug, Parser)]
#[command(about = "Runs Claude Code on a credential lent by the cyber-sandbox host")]
struct Courier {
    /// Socket the host publishes the current access token on.
    #[arg(long)]
    socket: PathBuf,
    /// File to write the credential into, where Claude Code reads it.
    #[arg(long)]
    credentials: PathBuf,
    /// Directory Claude Code is started in.
    #[arg(long)]
    directory: PathBuf,
    /// Carry on the conversation this session was last left in, if it has one.
    ///
    /// The host knows the researcher asked to come back to the session; only the session
    /// knows whether there is anything here to come back to. Asking Claude Code to
    /// continue a conversation that was never had is an error rather than a fresh start,
    /// so the two halves of the question are answered where each of them is known.
    #[arg(long)]
    continue_conversation: bool,
    /// Arguments Claude Code is started with.
    #[arg(last = true)]
    arguments: Vec<String>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let courier = Courier::parse();
    match run(&courier).await {
        Ok(status) => {
            std::process::ExitCode::from(u8::try_from(exit_code(status)).unwrap_or(u8::MAX))
        }
        Err(error) => {
            tracing::error!("{error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Lends the credential, runs Claude Code on it, and takes it back.
async fn run(courier: &Courier) -> Result<ExitStatus> {
    let stamp = Stamp::of_self().context("reading this process's own identity")?;
    // The first fetch is not allowed to fail: starting Claude Code without a credential
    // would land the researcher in a login prompt inside a machine that cannot complete
    // one, which is a worse answer than saying why here.
    lend(courier, stamp)
        .await
        .context("fetching the host's credential")?;

    let claude = spawn(courier).context("starting claude in the session")?;
    let status = supervise(courier, stamp, claude).await;

    // Whatever happened above, and before anything is reported: the loan is over.
    Credentials::remove(&courier.credentials)
        .await
        .context("taking back the credential")?;
    // And so is the way it arrived. sshd unlinks the forwarded socket when it tears the
    // channel down, but a connection cut rather than closed leaves the name behind, and
    // nothing else will ever ask for this one: it was named for this run alone.
    remove_if_present(&courier.socket)
        .await
        .context("taking back the socket the credential arrived on")?;
    status
}

/// Removes `path`, treating an absent file as the state that was asked for.
async fn remove_if_present(path: &Path) -> Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
    }
}

/// Runs Claude Code to completion, renewing the loan underneath it.
///
/// Claude Code is a child rather than a replacement for this process because the file has
/// to keep being rewritten while it runs, and because the process the file names has to
/// still be there for it to be read. That makes the terminal's interrupt this process's
/// problem too — it reaches the whole foreground process group — so it is received and
/// deliberately ignored here, leaving Claude Code to shut itself down.
async fn supervise(courier: &Courier, stamp: Stamp, mut claude: Child) -> Result<ExitStatus> {
    let mut interrupt = signal(SignalKind::interrupt()).context("listening for an interrupt")?;
    let mut terminate = signal(SignalKind::terminate()).context("listening for a termination")?;
    let mut hangup = signal(SignalKind::hangup()).context("listening for a hangup")?;
    let mut renewal = tokio::time::interval(REFRESH);
    renewal.tick().await;

    loop {
        tokio::select! {
            status = claude.wait() => return status.context("waiting for claude to finish"),
            _ = renewal.tick() => {
                // A failed renewal is not fatal: the credential already written stays
                // valid until it expires, and the next attempt is five minutes away.
                if let Err(error) = lend(courier, stamp).await {
                    tracing::warn!("could not renew the host's credential: {error:#}");
                }
            }
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
            _ = hangup.recv() => {}
        }
    }
}

/// Fetches the current token and writes it where Claude Code reads it.
async fn lend(courier: &Courier, stamp: Stamp) -> Result<()> {
    let bearer = fetch(&courier.socket).await?;
    let credentials = Credentials {
        env: cyber_sandbox_creds::bearer_environment(&bearer.token),
        expires_at: bearer.expires_at,
        pid: stamp.pid,
        proc_start: stamp.started,
    };
    credentials
        .write_to(&courier.credentials)
        .await
        .with_context(|| format!("writing {}", courier.credentials.display()))
}

/// Asks the host for the token it is currently prepared to lend.
async fn fetch(socket: &Path) -> Result<Bearer> {
    let stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("connecting to {}", socket.display()))?;
    Bearer::receive(stream)
        .await
        .context("reading the credential the host sent")
}

/// How Claude Code is started for a session.
fn spawn(courier: &Courier) -> Result<Child> {
    Command::new(CLAUDE)
        .args(arguments(courier)?)
        .current_dir(&courier.directory)
        .envs(cyber_sandbox_creds::launch_environment(
            &courier.credentials,
        ))
        .spawn()
        .with_context(|| format!("running {CLAUDE} in {}", courier.directory.display()))
}

/// The arguments Claude Code is given, once the session has answered what only it knows.
///
/// # Errors
/// Fails when the account has no home directory to look in.
fn arguments(courier: &Courier) -> Result<Vec<String>> {
    let mut arguments = courier.arguments.clone();
    if courier.continue_conversation && has_conversation()? {
        arguments.insert(0, CONTINUE.to_owned());
    }
    Ok(arguments)
}

/// Whether this session holds a conversation Claude Code could carry on.
///
/// Claude Code is only ever started in one directory here, so the question is whether it
/// has written any transcript at all — which is read from its own files, rather than by
/// reproducing the way it names the directory one belongs to.
fn has_conversation() -> Result<bool> {
    let home = std::env::var_os("HOME").context("this account has no HOME to look in")?;
    let mut pending = vec![PathBuf::from(home).join(TRANSCRIPTS)];
    while let Some(directory) = pending.pop() {
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            // Nothing has been written here yet, which is itself the answer.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("reading {}", directory.display()));
            }
        };
        for entry in entries {
            let entry = entry.with_context(|| format!("reading {}", directory.display()))?;
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|kind| kind == TRANSCRIPT) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// This process's identity, as Claude Code will go and check it.
#[derive(Debug, Clone, Copy)]
struct Stamp {
    pid: u32,
    started: Timestamp,
}

impl Stamp {
    /// Reads this process's own pid and start time.
    ///
    /// Claude Code learns the start time from `ps`, which reports whole seconds, and
    /// procps arrives at them by adding the process's start — counted in clock ticks
    /// since boot — to the boot time and truncating. The same arithmetic is done here, so
    /// that the two agree exactly rather than within the tolerance Claude Code allows.
    fn of_self() -> Result<Self> {
        let process = procfs::process::Process::myself().context("opening /proc/self")?;
        let stat = process.stat().context("reading /proc/self/stat")?;
        let boot = procfs::boot_time_secs().context("reading the boot time")?;
        let ticks = procfs::ticks_per_second();
        let started = i64::try_from(boot + stat.starttime / ticks)
            .context("the boot time is not a time this century")?;
        Ok(Self {
            pid: std::process::id(),
            started: Timestamp::from_second(started).context("the start time is not a time")?,
        })
    }
}

/// What a shell would report for `status`, so that a Claude Code killed by a signal is
/// not mistaken for one that merely returned nothing.
fn exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}
