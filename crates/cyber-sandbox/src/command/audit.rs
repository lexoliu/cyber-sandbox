use std::io::Write as _;

use anyhow::{Context as _, Result};
use cyber_sandbox_audit::{AuditEvent, AuditRecord, BlockReason, Endpoint, Transport};

use crate::{cli, host::Host};

/// Prints the tail of a sandbox's audit trail, optionally following it.
///
/// The trail is read through the runtime rather than a host mount: it is written inside
/// the guest by the gateway account and by nothing else, so reading it as that account
/// keeps the file out of reach of everything that runs sample code.
///
/// # Errors
/// Fails when no such sandbox is known, when the trail cannot be read, or when a record
/// in it is not a record this build understands.
pub async fn tail(host: &Host, arguments: &cli::AuditTail) -> Result<()> {
    let record = host.record(&arguments.id).await?;
    let name = Host::container_name(&record.id)?;
    let layout = host.layout();

    let mut command = vec![
        "tail".to_owned(),
        "-n".to_owned(),
        arguments.lines.to_string(),
    ];
    if arguments.follow {
        // `-F` rather than `-f`, because the gateway rotates the trail it is appending to.
        command.push("-F".to_owned());
    }
    command.push(layout.audit_trail().display().to_string());

    let mut stream = host
        .runtime()
        .exec_streaming(&name, &layout.gateway.name, &command)?;

    let mut stdout = std::io::stdout().lock();
    while let Some(line) = stream.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let record: AuditRecord = serde_json::from_str(&line)
            .with_context(|| format!("parsing an audit record: {line}"))?;
        writeln!(stdout, "{}", summarize(&record)).context("writing the audit trail")?;
        stdout.flush().context("writing the audit trail")?;
    }

    stream.finish().await.map_err(Into::into)
}

/// Copies a sandbox's whole audit trail out, unmodified.
///
/// The output is the gateway's own JSONL rather than the rendering `tail` prints, because
/// an exported trail is evidence: it has to stay byte-for-byte what the gateway recorded.
///
/// # Errors
/// Fails when no such sandbox is known, when the trail cannot be read, or when the
/// destination cannot be written.
pub async fn export(host: &Host, arguments: &cli::AuditExport) -> Result<()> {
    let record = host.record(&arguments.id).await?;
    let name = Host::container_name(&record.id)?;
    let layout = host.layout();

    let trail = host
        .runtime()
        .exec_as(
            &name,
            &layout.gateway.name,
            &["cat".to_owned(), layout.audit_trail().display().to_string()],
        )
        .await
        .context("reading the audit trail")?;

    match &arguments.output {
        Some(path) => tokio::fs::write(path, trail.stdout)
            .await
            .with_context(|| format!("writing {}", path.display())),
        None => std::io::stdout()
            .lock()
            .write_all(trail.stdout.as_bytes())
            .context("writing the audit trail"),
    }
}

/// One audited event as a single line a person can scan.
fn summarize(record: &AuditRecord) -> String {
    let uid = record
        .uid
        .map_or_else(|| "-".to_owned(), |uid| uid.to_string());
    format!("{} uid={uid} {}", record.at, event(&record.event))
}

fn event(event: &AuditEvent) -> String {
    match event {
        AuditEvent::Dns(query) => format!(
            "dns    {} {} -> {} ({}ms)",
            query.record_type,
            query.name,
            if query.answers.is_empty() {
                "no answer".to_owned()
            } else {
                query
                    .answers
                    .iter()
                    .map(|answer| answer.data.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            },
            query.elapsed_ms
        ),
        AuditEvent::Connect(connect) => format!(
            "tcp    {} {}up/{}down ({}ms)",
            destination(&connect.destination, connect.resolved_from.as_deref()),
            connect.bytes_out,
            connect.bytes_in,
            connect.elapsed_ms
        ),
        AuditEvent::Tls(handshake) => format!(
            "tls    {} sni={} alpn={} cert={}",
            destination(&handshake.destination, None),
            handshake.server_name.as_deref().unwrap_or("-"),
            handshake.alpn.as_deref().unwrap_or("-"),
            &handshake.upstream_cert_sha256[..16.min(handshake.upstream_cert_sha256.len())]
        ),
        AuditEvent::Http(exchange) => format!(
            "http   {} {} -> {} ({}B in, {}B out, {}ms)",
            exchange.method,
            exchange.url,
            exchange.status,
            exchange.response_bytes,
            exchange.request_bytes,
            exchange.elapsed_ms
        ),
        AuditEvent::Blocked(blocked) => format!(
            "BLOCK  {} {} {}",
            transport(blocked.transport),
            destination(&blocked.destination, None),
            reason(blocked.reason)
        ),
    }
}

fn destination(endpoint: &Endpoint, resolved_from: Option<&str>) -> String {
    match resolved_from {
        Some(name) => format!("{}:{} ({name})", endpoint.ip, endpoint.port),
        None => format!("{}:{}", endpoint.ip, endpoint.port),
    }
}

const fn transport(transport: Transport) -> &'static str {
    match transport {
        Transport::Tcp => "tcp",
        Transport::Udp => "udp",
        Transport::Other => "other",
    }
}

const fn reason(reason: BlockReason) -> &'static str {
    match reason {
        BlockReason::UnauditableTransport => "the transport cannot be audited in cleartext",
        BlockReason::NoHandler => "no transparent handler for the destination port",
        BlockReason::UpstreamUnreachable => "the upstream connection failed",
    }
}
