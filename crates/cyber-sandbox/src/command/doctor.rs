use std::io::Write as _;

use anyhow::{Context as _, Result};
use askama::Template;
use cyber_sandbox_runtime::ImageReference;

use crate::{cli, host::Host};

/// One line of the readiness report.
#[derive(Debug)]
pub struct Check {
    /// What was checked.
    pub name: String,
    /// `ok`, `fixed` or `failed`.
    pub status: String,
    /// Evidence for the status.
    pub detail: String,
}

impl Check {
    fn ok(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.to_owned(),
            status: "ok".to_owned(),
            detail: detail.into(),
        }
    }

    fn fixed(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.to_owned(),
            status: "fixed".to_owned(),
            detail: detail.into(),
        }
    }

    fn failed(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.to_owned(),
            status: "failed".to_owned(),
            detail: detail.into(),
        }
    }

    fn is_failure(&self) -> bool {
        self.status == "failed"
    }
}

/// The readiness report.
#[derive(Debug, Template)]
#[template(path = "doctor.txt", escape = "none")]
struct Report {
    checks: Vec<Check>,
    ready: bool,
    fix: bool,
}

/// Reports whether the host can run sandboxes, repairing what `--fix` allows.
///
/// # Errors
/// Fails only when the report cannot be written. A failing check is reported as a
/// non-zero exit rather than an error, because the report itself is the answer.
pub async fn run(host: &Host, arguments: &cli::Doctor) -> Result<bool> {
    let runtime = host.runtime();
    let mut checks = vec![Check::ok(
        "runtime binary",
        runtime.binary().display().to_string(),
    )];

    match runtime.version().await {
        Ok(version) => checks.push(Check::ok("runtime version", version)),
        Err(error) => checks.push(Check::failed("runtime version", error.to_string())),
    }

    checks.push(system_services(host, arguments.fix).await);
    checks.push(sandbox_image(host).await);
    checks.push(host_tool("ssh client", "ssh"));
    checks.push(host_tool("claude code", "claude"));
    checks.push(host_tool("codex", "codex"));

    let ready = !checks.iter().any(Check::is_failure);
    let report = Report {
        checks,
        ready,
        fix: arguments.fix,
    }
    .render()
    .context("rendering the readiness report")?;
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(report.as_bytes())
        .context("writing the readiness report")?;
    Ok(ready)
}

async fn system_services(host: &Host, fix: bool) -> Check {
    let runtime = host.runtime();
    let reason = match runtime.system_status().await {
        Ok(status) if status.is_running() => {
            return Check::ok("system services", status.api_server_version);
        }
        Ok(status) => format!("the API server reports `{}`", status.status),
        Err(error) => error.to_string(),
    };
    if !fix {
        return Check::failed("system services", reason);
    }
    match runtime.system_start().await {
        Ok(()) => Check::fixed("system services", "started"),
        Err(error) => Check::failed("system services", error.to_string()),
    }
}

async fn sandbox_image(host: &Host) -> Check {
    let Ok(reference) = ImageReference::new(cli::DEFAULT_IMAGE) else {
        return Check::failed("sandbox image", "the default image tag is not a reference");
    };
    match host.runtime().image_exists(&reference).await {
        Ok(true) => Check::ok("sandbox image", cli::DEFAULT_IMAGE),
        Ok(false) => Check::failed(
            "sandbox image",
            format!(
                "{} is not built; run `cyber-sandbox image build`",
                cli::DEFAULT_IMAGE
            ),
        ),
        Err(error) => Check::failed("sandbox image", error.to_string()),
    }
}

fn host_tool(name: &str, binary: &str) -> Check {
    match find_on_path(binary) {
        Some(path) => Check::ok(name, path),
        None => Check::failed(name, format!("`{binary}` is not on PATH")),
    }
}

fn find_on_path(binary: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(binary))
        .find(|candidate| candidate.is_file())
        .map(|found| found.display().to_string())
}
