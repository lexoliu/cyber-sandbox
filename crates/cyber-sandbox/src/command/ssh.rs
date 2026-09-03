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
pub async fn run(host: &Host, arguments: &cli::Ssh) -> Result<()> {
    let record = host.record(&arguments.id).await?;
    let address = host.address_of(&Host::container_name(&record.id)?).await?;
    let endpoint = record.endpoint(address);

    let mut client = std::process::Command::new("ssh");
    client.args(endpoint.ssh_arguments());
    if arguments.command.is_empty() {
        // A login shell in the work directory is what a researcher wants by default, and
        // `cd` has to be part of the remote command because sshd starts in the home.
        client.arg(format!(
            "cd {} && exec $SHELL -l",
            shell_quote(&record.work_dir.display().to_string())
        ));
    } else {
        client.args(&arguments.command);
    }

    Err(client.exec()).with_context(|| format!("running ssh to reach `{}`", record.id))
}

/// Quotes `value` for a POSIX shell, since the remote command is interpreted by one.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::shell_quote;

    #[test]
    fn a_path_holding_a_quote_cannot_escape_the_remote_command() {
        assert_eq!(shell_quote("/srv/work"), "'/srv/work'");
        assert_eq!(shell_quote("/srv/it's"), r"'/srv/it'\''s'");
    }
}
