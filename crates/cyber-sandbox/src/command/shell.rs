use std::os::unix::process::CommandExt as _;

use anyhow::{Context as _, Result};

use crate::{
    cli,
    command::{banner, shell_quote},
    handoff::Handoff,
    host::Host,
    provision,
};

/// Opens a shell, or runs a command, inside an isolated research session.
///
/// The `ssh` client replaces this process rather than being supervised by it, so the
/// session gets a real controlling terminal, job control and signal handling, and the
/// client's exit status becomes cyber-sandbox's own. That is also why nothing is cleaned
/// up afterwards: this process is gone by then, and the session's machine is reclaimed on
/// the way in to the next one instead.
///
/// # Errors
/// Fails when the session cannot be opened, or when `ssh` cannot be executed at all. It
/// never returns on success, because this process ceases to exist.
pub async fn run(host: &Host, arguments: &cli::Shell) -> Result<()> {
    let session = provision::open(host, &arguments.attach).await?;
    let record = &session.record;
    let handoff = Handoff::from_host(host.layout());
    banner(host, &session, &handoff, "shell")?;

    let known_hosts = host.known_hosts_of(&record.id).await?;
    let endpoint = record.endpoint(session.address, known_hosts, handoff.sent());

    let mut client = std::process::Command::new("ssh");
    client.args(endpoint.ssh_arguments());
    client.arg(remote_command(
        &record.work_dir.display().to_string(),
        &arguments.command,
    ));

    Err(client.exec()).with_context(|| format!("opening session {}", record.id))
}

/// What the session is asked to run, starting in the session's work directory.
///
/// The `cd` is part of the remote command because sshd starts every session in the
/// account's home, and a command runs where an interactive shell would land rather than
/// somewhere the researcher was never shown.
fn remote_command(work_dir: &str, command: &[String]) -> String {
    let run = if command.is_empty() {
        // A login shell is what a researcher wants when they asked for nothing else.
        "exec $SHELL -l".to_owned()
    } else {
        // `ssh` joins a multi-word command with spaces before sending it, so the parts
        // arrive as one line either way; joining here only makes that explicit.
        command.join(" ")
    };
    format!("cd {} && {run}", shell_quote(work_dir))
}

#[cfg(test)]
mod tests {
    use super::remote_command;

    #[test]
    fn a_session_starts_where_the_samples_are_mounted() {
        assert_eq!(remote_command("/work", &[]), "cd '/work' && exec $SHELL -l");
    }

    #[test]
    fn a_command_runs_where_a_shell_would_have_landed() {
        let command = ["file".to_owned(), "sample.bin".to_owned()];
        assert_eq!(
            remote_command("/work", &command),
            "cd '/work' && file sample.bin",
            "a command that lands in the home directory cannot see the samples the \
             session was started for"
        );
    }
}
