//! Implementations of the individual commands.

pub mod audit;
pub mod codex;
pub mod shell;

use std::io::Write as _;

use anyhow::{Context as _, Result};
use askama::Template;

use crate::{host::Host, provision};

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
}

/// Tells the researcher what they are about to be dropped into, where `command` is the
/// subcommand that would reopen this session.
///
/// Written to standard error, because the session's own output is what belongs on
/// standard output — a `cyber-sandbox shell -- file sample.bin` piped into something else
/// must not have this in front of it.
pub fn banner(host: &Host, session: &provision::Session, command: &'static str) -> Result<()> {
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
    }
    .render()
    .context("rendering the session summary")?;
    std::io::stderr()
        .lock()
        .write_all(text.as_bytes())
        .context("writing the session summary")
}
