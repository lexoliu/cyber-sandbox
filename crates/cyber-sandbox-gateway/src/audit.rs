use std::path::Path;

use cyber_sandbox_audit::{AuditEvent, AuditRecord, AuditWriter};
use jiff::Timestamp;
use tokio::{sync::mpsc, task::JoinHandle};

use crate::error::Result;

/// Number of records that may queue up before producers wait for the writer.
///
/// A bounded channel is what makes the gateway fail closed under audit pressure: when the
/// trail cannot keep up, the connections producing records slow down rather than the
/// records being dropped.
const QUEUE_DEPTH: usize = 1024;

/// Handle every connection uses to report what it observed.
///
/// The audit trail has exactly one writer — the task [`spawn`] owns — and every producer
/// reaches it through this channel, so no lock is ever taken on the file.
#[derive(Debug, Clone)]
pub struct AuditSink {
    sandbox: String,
    records: mpsc::Sender<AuditRecord>,
}

impl AuditSink {
    /// Appends one event to the trail, waiting if the writer is behind.
    pub async fn record(&self, event: AuditEvent) {
        self.record_as(None, event).await;
    }

    /// Appends one event attributed to the uid that produced it.
    ///
    /// Only the packet filter knows which account a refused packet came from, so this is
    /// the one path that can name it.
    pub async fn record_as(&self, uid: Option<u32>, event: AuditEvent) {
        let record = AuditRecord {
            at: Timestamp::now(),
            sandbox: self.sandbox.clone(),
            uid,
            event,
        };
        if self.records.send(record).await.is_err() {
            tracing::error!(
                "the audit writer stopped; the gateway can no longer account for traffic"
            );
        }
    }
}

/// Starts the single audit writer and returns the handle producers clone.
///
/// # Errors
/// Fails when the trail cannot be opened for appending.
pub async fn spawn(sandbox: &str, trail: &Path) -> Result<(AuditSink, JoinHandle<()>)> {
    let mut writer = AuditWriter::open(trail).await?;
    let (records, mut incoming) = mpsc::channel(QUEUE_DEPTH);
    let task = tokio::spawn(async move {
        while let Some(record) = incoming.recv().await {
            if let Err(error) = writer.append(&record).await {
                tracing::error!(%error, "failed to append an audit record");
            }
        }
    });
    Ok((
        AuditSink {
            sandbox: sandbox.to_owned(),
            records,
        },
        task,
    ))
}
