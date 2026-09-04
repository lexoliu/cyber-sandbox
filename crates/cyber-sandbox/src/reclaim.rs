//! Taking sessions away, which nobody asks for either.
//!
//! Every session leaves a virtual machine, a disk image and an SSH identity behind, and
//! there is no command for deleting one: a researcher who has finished with an
//! environment closes the shell, and the tool is left to notice. So it is noticed here,
//! on the way in to the next session, on two grounds.
//!
//! The first is age. A session nobody has opened in [`IDLE_LIMIT`] is not being resumed;
//! keeping it only makes the picker longer and the disk fuller.
//!
//! The second is room. The runtime's state volume is shared with macOS's swapfile, and
//! filling it is what wedged this host once already, so a session that would be created
//! below the sandbox disk floor takes the least recently opened ones with it until the
//! floor is clear again.
//!
//! A machine the runtime is currently running is never touched by either rule. It may be
//! holding a researcher's shell, and no amount of disk pressure justifies pulling a
//! debugger out from under someone.

use std::time::Duration;

use anyhow::{Context as _, Result};
use cyber_sandbox_runtime::{ContainerState, RunState, Sandbox, Workload};
use jiff::Timestamp;

use crate::{host::Host, keys::SandboxKey, session::SessionRecord};

/// How long a session may go unopened before it is reclaimed.
///
/// A week: long enough to span a holiday and come back to the environment an
/// investigation was left in, short enough that abandoned ones do not accumulate.
pub const IDLE_LIMIT: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Makes room for a session that is about to be created.
///
/// # Errors
/// Fails when the host's state or the runtime's containers cannot be read, or when a
/// machine that should go cannot be deleted. It does not fail for a host that is still
/// short of disk afterwards: the budget refuses that, with a message about the host
/// rather than about reclamation.
pub async fn make_room(host: &Host) -> Result<()> {
    let live = host
        .runtime()
        .list()
        .await
        .context("listing the runtime's containers")?;
    let now = Timestamp::now();

    // Least recently opened first: that is the order both rules reclaim in.
    let mut candidates = host.sessions().await?;
    candidates.retain(|record| !is_running(&live, record));
    candidates.reverse();

    let mut recent = Vec::new();
    for record in candidates {
        if record.idle_for(now) >= IDLE_LIMIT {
            tracing::info!(
                session = %record.id,
                idle = %crate::session::describe_age(record.idle_for(now)),
                "reclaiming a session nobody has come back to"
            );
            remove(host, &record).await?;
        } else {
            recent.push(record);
        }
    }

    for record in recent {
        if host.budget().await?.free_disk() >= <Sandbox as Workload>::DISK_FLOOR {
            return Ok(());
        }
        tracing::info!(
            session = %record.id,
            "reclaiming the least recently opened session to make room on the disk"
        );
        remove(host, &record).await?;
    }
    Ok(())
}

/// Takes one session away completely: its machine, its identity, its host key and its
/// record.
///
/// A machine the runtime has already forgotten is not an error, because the host's own
/// state still has to go — that is exactly the state a half-deleted session leaves
/// behind, and leaving it would offer the researcher a session that cannot be opened.
///
/// # Errors
/// Fails when the runtime refuses to delete the machine, or when the host's own state
/// cannot be removed.
pub async fn remove(host: &Host, record: &SessionRecord) -> Result<()> {
    let name = record.id.container_name()?;
    let live = host
        .runtime()
        .list()
        .await
        .context("listing the runtime's containers")?;
    if live.iter().any(|container| container.id == name) {
        host.runtime()
            .remove(&name)
            .await
            .context("deleting the session's machine")?;
    }
    // The agents' entries name an address the machine no longer has. They are written
    // when a session is opened and taken away when it goes, so that neither agent is ever
    // offered a machine that cannot answer — or worse, an address vmnet has since given
    // to a different one.
    host.agents()
        .unregister(record.id.as_str())
        .await
        .context("unregistering the session from the host's agents")?;
    SandboxKey::remove(&host.key_directory(), record.id.as_str()).await?;
    forget_host_key(host, record).await?;
    host.forget(&record.id).await?;
    tracing::info!(session = %record.id, "reclaimed");
    Ok(())
}

/// Drops the record of the host key this session's machine presented.
///
/// The next machine to be handed its vmnet address must be free to present a different
/// one, so the file goes when the session does.
async fn forget_host_key(host: &Host, record: &SessionRecord) -> Result<()> {
    let path = host.known_hosts_of(&record.id).await?;
    match tokio::fs::remove_file(&path).await {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(source).with_context(|| format!("removing {}", path.display())),
    }
}

/// Whether the runtime is running this session's machine right now.
#[must_use]
pub fn is_running(live: &[ContainerState], record: &SessionRecord) -> bool {
    live.iter().any(|container| {
        container.id.as_str() == record.id.as_str() && container.status.state == RunState::Running
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use cyber_sandbox_runtime::{Arch, ImageReference};

    use super::*;

    fn live() -> Vec<ContainerState> {
        serde_json::from_str(include_str!("../tests/data/containers.json")).unwrap()
    }

    fn record(id: &str, last_used: Timestamp) -> SessionRecord {
        SessionRecord {
            id: id.parse().unwrap(),
            image: ImageReference::new("localhost/cyber-sandbox:arm64").unwrap(),
            arch: Arch::Arm64,
            ssh_port: 22,
            researcher: "researcher".to_owned(),
            work_dir: PathBuf::from("/work"),
            samples: None,
            identity_file: PathBuf::from("/keys/id"),
            created_at: last_used,
            last_used,
        }
    }

    #[test]
    fn a_session_someone_is_working_in_is_never_a_candidate() {
        let ancient = Timestamp::now() - jiff::SignedDuration::from_hours(24 * 365);
        let running = record("c0ffee", ancient);
        assert!(
            is_running(&live(), &running),
            "no amount of disk pressure justifies deleting the machine a researcher's \
             shell is attached to, so a running one is excluded before age is even read"
        );
        assert!(!is_running(&live(), &record("dec0de", ancient)));
        assert!(!is_running(&live(), &record("abcdef", ancient)));
    }

    #[test]
    fn a_session_is_stale_only_once_a_whole_week_has_passed() {
        let now = Timestamp::now();
        let six_days = record("dec0de", now - jiff::SignedDuration::from_hours(24 * 6));
        let eight_days = record("dec0de", now - jiff::SignedDuration::from_hours(24 * 8));
        assert!(six_days.idle_for(now) < IDLE_LIMIT);
        assert!(eight_days.idle_for(now) >= IDLE_LIMIT);
    }
}
