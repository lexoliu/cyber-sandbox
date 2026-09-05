//! Implementations of the individual commands.

pub mod audit;
pub mod claude;
pub mod codex;
pub mod shell;

use std::io::Write as _;

use anyhow::{Context as _, Result};
use askama::Template;

use crate::{handoff::Handoff, host::Host, provision};

/// What is printed before the session is handed over.
#[derive(Debug, Template)]
#[template(path = "session.txt", escape = "none")]
struct Banner {
    created: bool,
    command: &'static str,
    id: String,
    image: String,
    arch: String,
    samples: String,
    work_dir: String,
    keys: String,
}

/// Tells the researcher what they are about to be dropped into, where `command` is the
/// subcommand that would reopen this session.
///
/// Written to standard error, because the session's own output is what belongs on
/// standard output — a `cyber-sandbox shell -- file sample.bin` piped into something else
/// must not have this in front of it.
pub fn banner(
    host: &Host,
    session: &provision::Session,
    handoff: &Handoff,
    command: &'static str,
) -> Result<()> {
    let record = &session.record;
    let text = Banner {
        created: session.created,
        command,
        id: record.id.to_string(),
        image: record.image.to_string(),
        arch: record.arch.to_string(),
        samples: record.samples.as_ref().map_or_else(
            || "none mounted".to_owned(),
            |path| {
                format!(
                    "{} \u{2192} {}",
                    path.display(),
                    host.layout().samples_dir.display()
                )
            },
        ),
        work_dir: record.work_dir.display().to_string(),
        keys: handoff.summary(),
    }
    .render()
    .context("rendering the session summary")?;
    std::io::stderr()
        .lock()
        .write_all(text.as_bytes())
        .context("writing the session summary")
}

/// Quotes `value` for a POSIX shell, since a remote command is interpreted by one.
///
/// Every path this tool sends across is one it made itself, so this is not the difference
/// between working and broken — it is the difference between a session that goes wrong
/// where a path holds a quote and one that cannot be made to run something else by it.
pub fn shell_quote(value: &str) -> String {
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
