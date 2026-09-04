//! Running Claude Code inside a session.
//!
//! Claude Code has no split between a model side and a tool side: it is one program, and
//! it runs where the work is. So unlike Codex it runs *inside* the session, and needs a
//! credential there — which is the whole difficulty, since the machine it runs on is the
//! one executing untrusted code.
//!
//! What crosses is an access token and nothing more. It is fetched over a unix socket the
//! host owns and ssh publishes inside the session, by a courier that writes it where
//! Claude Code reads a host-managed credential from, starts Claude Code, fetches a fresh
//! one before the old one runs out, and takes the file away again when Claude Code exits.
//! The refresh token that could mint further tokens never leaves the host's keychain: a
//! session gets the few hours the token it was lent has left, and nothing beyond them.
//!
//! Running inside the session is also why this is the one agent that gets the researcher's
//! subscription rather than an API key — usage, connectors and all — and why it can be run
//! with every permission prompt off. The session is the sandbox.

use std::{
    os::unix::process::ExitStatusExt as _,
    path::{Path, PathBuf},
    process::ExitStatus,
};

use anyhow::{Context as _, Result};
use cyber_sandbox_agents::{ClaudeLogin, SandboxEndpoint};
use tokio::{
    process::Command,
    signal::unix::{SignalKind, signal},
};

use crate::{
    cli,
    command::{banner, shell_quote},
    host::Host,
    loan::{Attachment, Loan},
    provision,
};

/// The courier, which is what the session is actually asked to run.
const COURIER: &str = "/usr/local/bin/cyber-sandbox-courier";

/// How Claude Code is asked to run: never stopping to ask.
///
/// The session is the sandbox. Claude Code's permission prompts are built for a laptop
/// holding the researcher's own files, and a machine whose disk is meant to be thrown
/// away and whose every packet is already audited has nothing left for them to protect —
/// only an autonomous agent to turn back into a manual one.
const AUTONOMOUS: &str = "--dangerously-skip-permissions";

/// Tells the courier the researcher came back to this session rather than made one.
///
/// Not `--continue` to Claude Code itself: that is refused outright when there is no
/// conversation, and a machine can be reopened without ever having held one. What the
/// host knows is the intent; whether there is a transcript to carry on is known in the
/// session, so the courier is the one that decides.
const CARRY_ON: &str = "--continue-conversation";

/// Opens Claude Code on an isolated research session.
///
/// # Errors
/// Fails when the researcher has no Claude Code login to lend from, when the session
/// cannot be opened, or when `ssh` cannot be started. Claude Code's own exit status
/// becomes cyber-sandbox's, so a failing run is reported as one.
pub async fn run(host: &Host, arguments: &cli::Claude) -> Result<()> {
    // Read before anything is built or started, because the socket it will be lent over
    // can only be named once the session has one: a researcher who is not logged in is
    // told so now rather than by a machine that has already spent a minute booting.
    let login = ClaudeLogin::discover();
    login.bearer().await.with_context(|| {
        format!(
            "reading the Claude Code login stored under `{}`; running `claude` once on the \
             host is what puts it there",
            login.service()
        )
    })?;

    let session = provision::open(host, &arguments.attach).await?;
    let record = &session.record;
    banner(host, &session, "claude")?;

    let attachment = Attachment::random(record.id.clone())?;
    let loan = Loan::open(login, host.loan_socket(&attachment)).await?;

    let known_hosts = host.known_hosts_of(&record.id).await?;
    let endpoint = record.endpoint(session.address, known_hosts);
    let runtime_dir = &host.layout().runtime_dir;
    let errand = Errand {
        socket: runtime_dir.join(attachment.socket_name()),
        credentials: runtime_dir.join(attachment.credentials_name()),
        directory: record.work_dir.clone(),
        resumed: arguments.attach.resume.is_some(),
    };

    let status = supervise(&endpoint, &errand, loan.socket()).await;

    // Whatever the run did: the socket is the researcher's login, and one left on disk is
    // one a later process on this host could still fetch a token from.
    loan.close().await?;

    match status? {
        status if status.success() => Ok(()),
        status => std::process::exit(exit_code(status)),
    }
}

/// What the session is asked to do, in the session's own terms.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Errand {
    /// Where the loan socket appears inside the session.
    socket: PathBuf,
    /// Where the courier writes the credential for Claude Code to read.
    credentials: PathBuf,
    /// Directory Claude Code works in.
    directory: PathBuf,
    /// Whether this session is being reopened rather than created.
    resumed: bool,
}

/// Runs the session's Claude Code to completion, outliving the signals that end it.
///
/// `ssh` is a child rather than a replacement for this process, because this process is
/// the one holding the socket the session fetches its token from — replacing it would
/// take the credential away at the moment the session first asked for one. That makes the
/// terminal's interrupt this process's problem too: it reaches the whole foreground
/// process group, so it is received and deliberately ignored here, leaving Claude Code to
/// shut itself down while the parent survives long enough to take the socket back.
async fn supervise(
    endpoint: &SandboxEndpoint,
    errand: &Errand,
    host_socket: &Path,
) -> Result<ExitStatus> {
    let mut interrupt = signal(SignalKind::interrupt()).context("listening for an interrupt")?;
    let mut terminate = signal(SignalKind::terminate()).context("listening for a termination")?;
    let mut hangup = signal(SignalKind::hangup()).context("listening for a hangup")?;

    let mut client = invocation(endpoint, errand, host_socket)
        .spawn()
        .context("opening the session")?;

    loop {
        tokio::select! {
            status = client.wait() => return status.context("waiting for the session to finish"),
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
            _ = hangup.recv() => {}
        }
    }
}

/// How `ssh` is invoked to put Claude Code on the far side of it.
fn invocation(endpoint: &SandboxEndpoint, errand: &Errand, host_socket: &Path) -> Command {
    let mut command = Command::new("ssh");
    command.args([
        // Claude Code is a full-screen program and the researcher is sitting in front of
        // it, so the session needs a terminal of its own; ssh only allocates one for a
        // remote command when asked twice.
        "-t",
        "-t",
        "-o",
        // Without this the forward failing is a warning, and what follows is a Claude
        // Code with no credential to fetch — which fails much later and says nothing
        // about a socket.
        "ExitOnForwardFailure=yes",
        "-R",
    ]);
    command.arg(forward(&errand.socket, host_socket));
    // The destination is the last of these, so everything of ours goes in front of it.
    command.args(endpoint.ssh_arguments());
    command.arg(errand.remote_command());
    command
}

/// The `-R` specification publishing the host's socket inside the session.
fn forward(guest_socket: &Path, host_socket: &Path) -> String {
    format!("{}:{}", guest_socket.display(), host_socket.display())
}

impl Errand {
    /// The one command the session runs, as a shell there will read it.
    ///
    /// The courier is exec'd rather than run under a shell, so the process the session's
    /// sshd is waiting on is the courier itself: a connection that drops takes the
    /// courier with it, and the courier taking the credential file away is what happens
    /// when it goes.
    fn remote_command(&self) -> String {
        let mut parts = vec![
            "exec".to_owned(),
            COURIER.to_owned(),
            "--socket".to_owned(),
            shell_quote(&self.socket.display().to_string()),
            "--credentials".to_owned(),
            shell_quote(&self.credentials.display().to_string()),
            "--directory".to_owned(),
            shell_quote(&self.directory.display().to_string()),
        ];
        if self.resumed {
            parts.push(CARRY_ON.to_owned());
        }
        parts.push("--".to_owned());
        parts.push(AUTONOMOUS.to_owned());
        parts.join(" ")
    }
}

/// What a shell would report for `status`, so that a session killed by a signal is not
/// mistaken for one that merely returned nothing.
fn exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint() -> SandboxEndpoint {
        SandboxEndpoint {
            id: "c0ffee".to_owned(),
            user: "researcher".to_owned(),
            host: "192.168.65.40".to_owned(),
            port: 22,
            identity_file: PathBuf::from("/state/keys/c0ffee"),
            known_hosts: PathBuf::from("/state/known_hosts/c0ffee"),
            start_directory: PathBuf::from("/work"),
        }
    }

    fn errand(resumed: bool) -> Errand {
        Errand {
            socket: PathBuf::from("/run/cyber-sandbox/c0ffee-1a2b3c4d.sock"),
            credentials: PathBuf::from("/run/cyber-sandbox/c0ffee-1a2b3c4d.json"),
            directory: PathBuf::from("/work"),
            resumed,
        }
    }

    fn arguments(resumed: bool) -> Vec<String> {
        invocation(
            &endpoint(),
            &errand(resumed),
            Path::new("/Users/researcher/.cyber-sandbox/run/c0ffee-1a2b3c4d.sock"),
        )
        .as_std()
        .get_args()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect()
    }

    #[test]
    fn the_token_socket_is_published_into_the_session_rather_than_out_of_it() {
        let arguments = arguments(false);
        let forward = arguments
            .windows(2)
            .find(|pair| pair[0] == "-R")
            .map(|pair| pair[1].clone())
            .expect("the forward is what the session fetches its token over");

        assert_eq!(
            forward,
            "/run/cyber-sandbox/c0ffee-1a2b3c4d.sock:\
             /Users/researcher/.cyber-sandbox/run/c0ffee-1a2b3c4d.sock",
            "the guest path comes first: a local forward would instead let the host \
             originate connections through the machine running samples"
        );
    }

    #[test]
    fn a_forward_that_could_not_be_made_stops_the_session_rather_than_starting_it() {
        assert!(
            arguments(false)
                .windows(2)
                .any(|pair| pair == ["-o", "ExitOnForwardFailure=yes"]),
            "the default is a warning, and what follows it is a Claude Code whose \
             credential fetch fails minutes later with nothing said about a socket"
        );
    }

    #[test]
    fn the_credential_never_appears_on_the_command_line() {
        let arguments = arguments(true).join(" ");
        assert!(
            !arguments.contains("sk-ant") && !arguments.contains("TOKEN"),
            "a command line is readable by every process on both machines, so the token \
             crosses over the socket and only over the socket: {arguments}"
        );
    }

    #[test]
    fn the_session_runs_the_courier_and_not_the_agent_directly() {
        let remote = errand(false).remote_command();
        assert!(
            remote.starts_with(&format!("exec {COURIER} ")),
            "sshd waits on the process it started, so the courier has to be that process \
             for the credential to be taken away when the connection drops: {remote}"
        );
        assert!(remote.contains(AUTONOMOUS));
    }

    #[test]
    fn only_a_reopened_session_is_asked_to_carry_a_conversation_on() {
        assert!(
            !errand(false).remote_command().contains(CARRY_ON),
            "a machine that was created a moment ago was not come back to"
        );
        let remote = errand(true).remote_command();
        assert!(remote.contains(CARRY_ON));
        assert!(
            remote.find(CARRY_ON) < remote.find(" -- "),
            "the courier is the one that decides, so this is its flag and not one passed \
             through to claude: {remote}"
        );
    }

    #[test]
    fn a_signalled_run_is_reported_the_way_a_shell_would() {
        assert_eq!(exit_code(ExitStatus::from_raw(2 << 8)), 2);
        assert_eq!(exit_code(ExitStatus::from_raw(9)), 137);
    }
}
