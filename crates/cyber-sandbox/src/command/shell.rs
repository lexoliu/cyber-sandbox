use std::os::unix::process::CommandExt as _;

use anyhow::{Context as _, Result};

use crate::{cli, host::Host};

/// Opens a shell, or runs a command, inside a running sandbox.
///
/// The `ssh` client replaces this process rather than being supervised by it, so the
/// session gets a real controlling terminal, job control and signal handling, and the
/// client's exit status becomes cyber-sandbox's own.
///
/// # Errors
/// Fails when no such sandbox is known, or when `ssh` cannot be executed at all. It
/// never returns on success, because this process ceases to exist.
pub async fn run(host: &Host, arguments: &cli::Shell) -> Result<()> {
    let record = host.record(&arguments.id).await?;
    let address = host.address_of(&Host::container_name(&record.id)?).await?;
    let endpoint = record.endpoint(address, host.known_hosts_of(&record.id).await?);

    let mut client = std::process::Command::new("ssh");
    client.args(endpoint.ssh_arguments());
    client.arg(remote_command(
        &record.work_dir.display().to_string(),
        &arguments.command,
    ));

    Err(client.exec()).with_context(|| format!("opening a session in `{}`", record.id))
}

/// What the sandbox is asked to run, starting in the sandbox's work directory.
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

/// Quotes `value` for a POSIX shell, since the remote command is interpreted by one.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::{remote_command, shell_quote};

    #[test]
    fn a_path_holding_a_quote_cannot_escape_the_remote_command() {
        assert_eq!(shell_quote("/srv/work"), "'/srv/work'");
        assert_eq!(shell_quote("/srv/it's"), r"'/srv/it'\''s'");
    }

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
             sandbox was started for"
        );
    }
}
