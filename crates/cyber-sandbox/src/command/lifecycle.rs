use std::{
    io::Write as _,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use anyhow::{Context as _, Result, bail};
use askama::Template;
use cyber_sandbox_runtime::{
    Capability, ContainerName, ContainerSpec, ContainerState, Cpus, HostBudget, ImageReference,
    Memory, Mount, Reservation, RunState, Sandbox,
};
use jiff::Timestamp;

use crate::{cli, command::image, host::Host, keys::SandboxKey, record::SandboxRecord};

/// How long the sandbox has to obtain an address and answer on its SSH port.
const READY_TIMEOUT: Duration = Duration::from_secs(120);

/// How often readiness is re-checked while waiting.
const READY_INTERVAL: Duration = Duration::from_millis(500);

/// Environment the entrypoint reads its per-sandbox facts from.
const NAME_VARIABLE: &str = "CYBER_SANDBOX_NAME";
const RESOLVER_VARIABLE: &str = "CYBER_SANDBOX_RESOLVER";
const AUTHORIZED_KEY_VARIABLE: &str = "CYBER_SANDBOX_AUTHORIZED_KEY";

/// What `up` prints once the sandbox answers.
#[derive(Debug, Template)]
#[template(path = "started.txt", escape = "none")]
struct Started {
    id: String,
    user: String,
    address: String,
    ssh_port: u16,
    image: String,
    arch: String,
    samples: String,
    identity_file: String,
    claude_settings: String,
    codex_environments: String,
}

/// Brings a sandbox up, and registers it with both agents.
///
/// Creating one and starting one again are the same request — the caller wants the
/// sandbox running — so a machine that already exists is resumed rather than refused.
/// What resuming will not do is quietly ignore an argument it cannot honour: a machine's
/// architecture, image, size and mounts are settled when it is created, and an argument
/// that contradicts one of them is refused instead of handing back a sandbox other than
/// the one that was asked for.
///
/// # Errors
/// Fails when the image cannot be built, the runtime refuses the container, an argument
/// contradicts a machine that already exists, the sandbox does not become reachable in
/// time, or the agents' configuration cannot be written.
pub async fn up(host: &Host, arguments: &cli::Up) -> Result<()> {
    let name = Host::container_name(&arguments.id)?;
    let image = arguments
        .image
        .clone()
        .unwrap_or_else(|| cli::default_image(arguments.arch));

    let provisioned = match existing(host, &name).await? {
        Some(container) => resume(host, arguments, &image, &name, &container).await?,
        None => create(host, arguments, &image, &name).await?,
    };

    let layout = host.layout();
    let address = wait_until_reachable(host, &name, layout.ssh_port).await?;

    let record = SandboxRecord {
        id: arguments.id.clone(),
        image: image.clone(),
        arch: arguments.arch,
        ssh_port: layout.ssh_port,
        researcher: layout.researcher.name.clone(),
        work_dir: layout.work_dir.clone(),
        samples: provisioned.samples,
        identity_file: provisioned.identity_file,
        started_at: Timestamp::now(),
    };
    host.store(&record).await?;

    // The agents' configuration names a concrete address, so it is rewritten on every
    // start rather than only on the first one: a sandbox that came back on a different
    // address would otherwise leave both agents dialling the machine that has it now.
    let agents = host.agents();
    agents
        .register(&record.endpoint(address))
        .await
        .context("registering the sandbox with the host's agents")?;

    let started = Started {
        id: record.id.clone(),
        user: record.researcher.clone(),
        address: address.to_string(),
        ssh_port: record.ssh_port,
        image: record.image.to_string(),
        arch: record.arch.to_string(),
        samples: record.samples.as_ref().map_or_else(
            || "none mounted".to_owned(),
            |path| {
                format!(
                    "{} \u{2192} {}",
                    path.display(),
                    layout.samples_dir.display()
                )
            },
        ),
        identity_file: record.identity_file.display().to_string(),
        claude_settings: agents.claude_path().display().to_string(),
        codex_environments: agents.codex_path().display().to_string(),
    }
    .render()
    .context("rendering the startup summary")?;
    std::io::stdout()
        .lock()
        .write_all(started.as_bytes())
        .context("writing the startup summary")
}

/// What a sandbox is given when it is created, and keeps for as long as it exists.
///
/// A machine cannot be handed a different key or a different sample mount by starting it
/// again, so these are read back from the record on a resume rather than derived afresh
/// from arguments that no longer apply.
struct Provisioned {
    /// Host directory mounted read-only as the sample source, when one was given.
    samples: Option<PathBuf>,
    /// Private key whose public half the machine was built to accept.
    identity_file: PathBuf,
}

/// Creates a sandbox that does not exist yet.
async fn create(
    host: &Host,
    arguments: &cli::Up,
    image: &ImageReference,
    name: &ContainerName,
) -> Result<Provisioned> {
    let samples = canonical_samples(arguments.samples.as_deref())?;

    // Sizing is checked before anything is created, so a host that cannot carry another
    // sandbox refuses without leaving an identity or a container behind.
    let reservation = reservation(&host.budget().await?, arguments)?;
    tracing::info!(
        cpus = %reservation.cpus(),
        memory = %reservation.memory(),
        "the host can carry this sandbox"
    );

    let key = SandboxKey::load_or_create(&host.key_directory(), &arguments.id).await?;

    if !host.runtime().image_exists(image).await? {
        tracing::info!(image = %image, "the sandbox image is not built yet");
        image::run(
            host,
            &arguments.workspace,
            image.clone(),
            cli::DEFAULT_BASE_IMAGE,
            arguments.arch,
            arguments.profile,
        )
        .await?;
    }

    let spec = spec(
        host,
        arguments,
        image.clone(),
        name,
        &key,
        reservation,
        samples.clone(),
    );
    host.runtime()
        .run_detached(&spec)
        .await
        .context("starting the sandbox")?;

    Ok(Provisioned {
        samples,
        identity_file: key.identity_file().to_path_buf(),
    })
}

/// Starts a sandbox that already exists, refusing anything its shape cannot honour.
async fn resume(
    host: &Host,
    arguments: &cli::Up,
    image: &ImageReference,
    name: &ContainerName,
    container: &ContainerState,
) -> Result<Provisioned> {
    let record = host.record(&arguments.id).await.with_context(|| {
        format!(
            "`{name}` already exists but is not a sandbox this tool started; delete it \
             with `container delete {name}` or choose another name"
        )
    })?;

    let configuration = &container.configuration;
    let (cpus, memory) = configuration.resources.allocation()?;
    ensure_unchanged(
        name,
        "architecture",
        configuration.platform.architecture.as_str(),
        arguments.arch.as_str(),
    )?;
    ensure_unchanged(
        name,
        "image",
        configuration.image.reference.as_str(),
        image.as_str(),
    )?;
    if let Some(requested) = arguments.cpus {
        ensure_unchanged(
            name,
            "size",
            &format!("{cpus} vCPUs"),
            &format!("{requested} vCPUs"),
        )?;
    }
    if let Some(requested) = arguments.memory_mib {
        ensure_unchanged(
            name,
            "size",
            &format!("{} MiB of memory", memory.as_mib()),
            &format!("{requested} MiB of memory"),
        )?;
    }
    if let Some(requested) = canonical_samples(arguments.samples.as_deref())? {
        ensure_unchanged(
            name,
            "sample directory",
            &record.samples.as_ref().map_or_else(
                || "none".to_owned(),
                |samples| samples.display().to_string(),
            ),
            &requested.display().to_string(),
        )?;
    }

    if container.status.state == RunState::Running {
        tracing::info!(sandbox = %name, "already running");
    } else {
        // A stopped machine costs the host nothing and a started one costs its whole
        // allocation, so starting it is checked against the host exactly as creating it
        // is — for the size it already has, which is the only size it can come back at.
        let reservation = host.budget().await?.reserve::<Sandbox>(cpus, memory)?;
        tracing::info!(
            cpus = %reservation.cpus(),
            memory = %reservation.memory(),
            "the host can carry this sandbox again"
        );
        host.runtime()
            .start(name, &reservation)
            .await
            .context("starting the sandbox")?;
    }

    Ok(Provisioned {
        samples: record.samples,
        identity_file: record.identity_file,
    })
}

/// Refuses an argument that contradicts a machine that already exists.
fn ensure_unchanged(
    name: &ContainerName,
    what: &str,
    existing: &str,
    requested: &str,
) -> Result<()> {
    if existing != requested {
        bail!(
            "`{name}` already exists with {existing}, but was asked for {requested}; a \
             machine's {what} is settled when it is created, so destroy it with \
             `cyber-sandbox rm {name}` and start it again to change that"
        );
    }
    Ok(())
}

/// Stops a sandbox without destroying it.
///
/// # Errors
/// Fails when no such sandbox is known or the runtime cannot stop it.
pub async fn down(host: &Host, arguments: &cli::Target) -> Result<()> {
    let record = host.record(&arguments.id).await?;
    let name = Host::container_name(&record.id)?;
    host.runtime()
        .stop(&name)
        .await
        .context("stopping the sandbox")?;
    tracing::info!(sandbox = record.id, "stopped");
    Ok(())
}

/// Destroys a sandbox, removes its identity and unregisters it from both agents.
///
/// # Errors
/// Fails when the runtime cannot delete the container or the agents' configuration
/// cannot be written. A container the runtime has already forgotten is not an error,
/// because the host's own state still has to be cleaned up.
pub async fn rm(host: &Host, arguments: &cli::Target) -> Result<()> {
    let name = Host::container_name(&arguments.id)?;
    if existing(host, &name).await?.is_some() {
        host.runtime()
            .remove(&name)
            .await
            .context("deleting the sandbox")?;
    }
    host.agents()
        .unregister(&arguments.id)
        .await
        .context("unregistering the sandbox from the host's agents")?;
    SandboxKey::remove(&host.key_directory(), &arguments.id).await?;
    host.forget(&arguments.id).await?;
    tracing::info!(sandbox = arguments.id, "removed");
    Ok(())
}

/// One row of `ls`.
#[derive(Debug)]
pub struct Row {
    /// Sandbox name.
    pub id: String,
    /// Lifecycle state as the runtime reports it.
    pub state: String,
    /// Address the sandbox answers on, when it is running.
    pub address: String,
    /// Guest architecture.
    pub arch: String,
    /// Image the sandbox was started from.
    pub image: String,
}

/// The `ls` table.
#[derive(Debug, Template)]
#[template(path = "list.txt", escape = "none")]
struct Listing {
    sandboxes: Vec<Row>,
}

/// Lists every sandbox the host has started and what the runtime says about it.
///
/// # Errors
/// Fails when the host's state or the runtime's container list cannot be read.
pub async fn ls(host: &Host) -> Result<()> {
    let records = host.records().await?;
    let live = host
        .runtime()
        .list()
        .await
        .context("listing the runtime's containers")?;

    let listing = Listing {
        sandboxes: rows(records, &live),
    }
    .render()
    .context("rendering the sandbox listing")?;
    std::io::stdout()
        .lock()
        .write_all(listing.as_bytes())
        .context("writing the sandbox listing")
}

/// Joins what the host recorded with what the runtime currently reports.
///
/// The address comes from the runtime rather than the record, because a container that
/// has been stopped and started again is on a different address, and one that is merely
/// stopped is on none at all: printing the recorded address for either would offer an
/// endpoint that nothing is listening on.
fn rows(records: Vec<SandboxRecord>, live: &[ContainerState]) -> Vec<Row> {
    records
        .into_iter()
        .map(|record| {
            let container = live
                .iter()
                .find(|container| container.id.as_str() == record.id);
            Row {
                address: container
                    .filter(|container| container.status.state == RunState::Running)
                    .and_then(ContainerState::ipv4_address)
                    .map_or_else(
                        || "-".to_owned(),
                        |address| format!("{address}:{}", record.ssh_port),
                    ),
                state: container
                    .map_or("gone", |container| run_state(container.status.state))
                    .to_owned(),
                arch: record.arch.to_string(),
                image: record.image.to_string(),
                id: record.id,
            }
        })
        .collect()
}

const fn run_state(state: RunState) -> &'static str {
    match state {
        RunState::Running => "running",
        RunState::Stopped => "stopped",
        RunState::Starting => "starting",
        RunState::Stopping => "stopping",
    }
}

/// Sizes the sandbox: what the caller asked for where they said so, half of what the
/// host can spare everywhere else, and in either case checked against the host.
///
/// The suggestion is only consulted for the dimensions the caller left open, so a host
/// with too little spare to suggest an allocation still reports what was actually asked
/// for when the caller sized the sandbox themselves.
///
/// # Errors
/// Fails when the host cannot carry the requested — or the derived — allocation.
fn reservation(budget: &HostBudget, arguments: &cli::Up) -> Result<Reservation<Sandbox>> {
    let cpus = match arguments.cpus {
        Some(cpus) => Cpus::new(cpus),
        None => budget.suggest::<Sandbox>()?.cpus(),
    };
    let memory = match arguments.memory_mib {
        Some(mebibytes) => Memory::from_mib(mebibytes),
        None => budget.suggest::<Sandbox>()?.memory(),
    };
    budget.reserve(cpus, memory).map_err(Into::into)
}

fn spec(
    host: &Host,
    arguments: &cli::Up,
    image: ImageReference,
    name: &ContainerName,
    key: &SandboxKey,
    reservation: Reservation<Sandbox>,
    samples: Option<PathBuf>,
) -> ContainerSpec {
    let layout = host.layout();
    let mut spec = ContainerSpec::new(name.clone(), image, arguments.arch, reservation);

    // Neither capability below has a use inside the sandbox, so the runtime removes them
    // before the guest is even started.
    spec.cap_drop = vec![Capability::SysModule, Capability::SysAdmin];
    // NET_ADMIN is what the entrypoint installs the egress policy with, and it is not in
    // the runtime's default set. The entrypoint hands it to nothing else: it drops the
    // capability from the bounding set of the process tree that runs sample code, so only
    // the code between container start and sshd ever holds it. SYS_PTRACE is for the
    // debuggers and tracers in the analysis toolchain, which have to attach to the
    // processes they are analysing.
    spec.cap_add = vec![Capability::NetAdmin, Capability::SysPtrace];
    spec.init = true;

    if let Some(source) = samples {
        spec.mounts
            .push(Mount::read_only(source, layout.samples_dir.clone()));
    }

    spec.env
        .insert(NAME_VARIABLE.to_owned(), arguments.id.clone());
    spec.env
        .insert(RESOLVER_VARIABLE.to_owned(), arguments.resolver.to_string());
    spec.env.insert(
        AUTHORIZED_KEY_VARIABLE.to_owned(),
        key.authorized_key().to_owned(),
    );

    spec
}

fn canonical_samples(samples: Option<&std::path::Path>) -> Result<Option<PathBuf>> {
    samples
        .map(|path| {
            path.canonicalize()
                .with_context(|| format!("resolving the sample directory {}", path.display()))
        })
        .transpose()
}

/// The runtime's view of a container, when it has one.
async fn existing(host: &Host, name: &ContainerName) -> Result<Option<ContainerState>> {
    let containers = host
        .runtime()
        .list()
        .await
        .context("listing the runtime's containers")?;
    Ok(containers
        .into_iter()
        .find(|container| &container.id == name))
}

/// Waits until the sandbox has an address and sshd answers on it.
///
/// Both halves matter: the runtime reports an address as soon as the guest's interface is
/// configured, which is well before the entrypoint has installed the egress policy and
/// started sshd. Registering the agents against a sandbox that cannot yet be reached
/// would hand the user a connection that fails on first use.
async fn wait_until_reachable(
    host: &Host,
    name: &ContainerName,
    ssh_port: u16,
) -> Result<Ipv4Addr> {
    let deadline = tokio::time::Instant::now() + READY_TIMEOUT;
    let mut last = String::from("the runtime has not reported an address yet");

    while tokio::time::Instant::now() < deadline {
        match host.runtime().inspect(name).await {
            Ok(state) => match state.ipv4_address() {
                Some(address) if accepts(SocketAddr::from((address, ssh_port))).await => {
                    return Ok(address);
                }
                Some(address) => last = format!("{address}:{ssh_port} is not accepting yet"),
                None => "the runtime has not reported an address yet".clone_into(&mut last),
            },
            Err(error) => last = error.to_string(),
        }
        tokio::time::sleep(READY_INTERVAL).await;
    }

    bail!(
        "`{name}` did not become reachable within {}s: {last}. Its startup output is \
         available with `container logs {name}`",
        READY_TIMEOUT.as_secs()
    )
}

async fn accepts(address: SocketAddr) -> bool {
    matches!(
        tokio::time::timeout(READY_INTERVAL, tokio::net::TcpStream::connect(address)).await,
        Ok(Ok(_))
    )
}

#[cfg(test)]
mod tests {
    use cyber_sandbox_runtime::Arch;

    use super::*;

    /// Two containers as the runtime reports them: one running with an address, one
    /// stopped with none.
    fn live() -> Vec<ContainerState> {
        serde_json::from_str(include_str!("../../tests/data/containers.json")).unwrap()
    }

    fn record(id: &str) -> SandboxRecord {
        SandboxRecord {
            id: id.to_owned(),
            image: ImageReference::new("localhost/cyber-sandbox:latest").unwrap(),
            arch: Arch::Arm64,
            ssh_port: 22,
            researcher: "researcher".to_owned(),
            work_dir: PathBuf::from("/work"),
            samples: None,
            identity_file: PathBuf::from("/keys/id"),
            started_at: Timestamp::now(),
        }
    }

    #[test]
    fn a_stopped_sandbox_offers_no_address() {
        let rows = rows(vec![record("halted")], &live());
        assert_eq!(rows[0].state, "stopped");
        assert_eq!(
            rows[0].address, "-",
            "nothing is listening on the address it last had, so offering it would hand \
             out an endpoint that cannot be reached"
        );
    }

    #[test]
    fn a_running_sandbox_reports_the_address_it_has_now() {
        let rows = rows(vec![record("live")], &live());
        assert_eq!(
            rows[0].address, "192.168.65.29:22",
            "the runtime is the authority: a container that has been restarted is on a \
             different address than the one the host recorded"
        );
    }

    #[test]
    fn a_sandbox_the_runtime_has_forgotten_is_reported_as_gone() {
        let rows = rows(vec![record("vanished")], &live());
        assert_eq!(rows[0].state, "gone");
        assert_eq!(rows[0].address, "-");
    }
}
