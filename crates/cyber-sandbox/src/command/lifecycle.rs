use std::{
    io::Write as _,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use anyhow::{Context as _, Result, bail};
use askama::Template;
use cyber_sandbox_runtime::{
    Capability, ContainerName, ContainerSpec, Cpus, HostBudget, Memory, Mount, Reservation,
    RunState, Sandbox,
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

/// Starts a sandbox, waits for it to answer, and registers it with both agents.
///
/// # Errors
/// Fails when the image cannot be built, the runtime refuses the container, the sandbox
/// does not become reachable in time, or the agents' configuration cannot be written.
pub async fn up(host: &Host, arguments: &cli::Up) -> Result<()> {
    let name = Host::container_name(&arguments.id)?;
    ensure_absent(host, &name).await?;

    let key = SandboxKey::load_or_create(&host.key_directory(), &arguments.id).await?;
    let samples = canonical_samples(arguments.samples.as_deref())?;
    let reservation = reservation(&host.budget().await?, arguments)?;
    tracing::info!(
        cpus = %reservation.cpus(),
        memory = %reservation.memory(),
        "the host can carry this sandbox"
    );

    if !host.runtime().image_exists(&arguments.image).await? {
        tracing::info!(image = %arguments.image, "the sandbox image is not built yet");
        image::run(
            host,
            &arguments.workspace,
            arguments.image.clone(),
            cli::DEFAULT_BASE_IMAGE,
            arguments.arch,
            arguments.profile,
        )
        .await?;
    }

    let spec = spec(host, arguments, &name, &key, reservation, samples.clone());

    host.runtime()
        .run_detached(&spec)
        .await
        .context("starting the sandbox")?;

    let layout = host.layout();
    let address = wait_until_reachable(host, &name, layout.ssh_port).await?;

    let record = SandboxRecord {
        id: arguments.id.clone(),
        image: arguments.image.clone(),
        arch: arguments.arch,
        address,
        ssh_port: layout.ssh_port,
        researcher: layout.researcher.name.clone(),
        work_dir: layout.work_dir.clone(),
        samples,
        identity_file: key.identity_file().to_path_buf(),
        started_at: Timestamp::now(),
    };
    host.store(&record).await?;

    let agents = host.agents();
    agents
        .register(&record.endpoint())
        .await
        .context("registering the sandbox with the host's agents")?;

    let started = Started {
        id: record.id.clone(),
        user: record.researcher.clone(),
        address: record.address.to_string(),
        ssh_port: record.ssh_port,
        image: record.image.to_string(),
        arch: record.arch.to_string(),
        samples: record.samples.as_ref().map_or_else(
            || "none mounted".to_owned(),
            |path| format!("{} → {}", path.display(), layout.samples_dir.display()),
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
    if exists(host, &name).await? {
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

    let sandboxes = records
        .into_iter()
        .map(|record| {
            let state = live
                .iter()
                .find(|container| container.id.as_str() == record.id)
                .map(|container| run_state(container.status.state));
            Row {
                address: match state {
                    Some(_) => format!("{}:{}", record.address, record.ssh_port),
                    None => "-".to_owned(),
                },
                state: state.unwrap_or("gone").to_owned(),
                arch: record.arch.to_string(),
                image: record.image.to_string(),
                id: record.id,
            }
        })
        .collect();

    let listing = Listing { sandboxes }
        .render()
        .context("rendering the sandbox listing")?;
    std::io::stdout()
        .lock()
        .write_all(listing.as_bytes())
        .context("writing the sandbox listing")
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
/// # Errors
/// Fails when the host cannot carry the requested — or the derived — allocation.
fn reservation(budget: &HostBudget, arguments: &cli::Up) -> Result<Reservation<Sandbox>> {
    let suggested = budget.suggest::<Sandbox>()?;
    let cpus = arguments.cpus.map_or_else(|| suggested.cpus(), Cpus::new);
    let memory = arguments
        .memory_mib
        .map_or_else(|| suggested.memory(), Memory::from_mib);
    budget.reserve(cpus, memory).map_err(Into::into)
}

fn spec(
    host: &Host,
    arguments: &cli::Up,
    name: &ContainerName,
    key: &SandboxKey,
    reservation: Reservation<Sandbox>,
    samples: Option<PathBuf>,
) -> ContainerSpec {
    let layout = host.layout();
    let mut spec = ContainerSpec::new(
        name.clone(),
        arguments.image.clone(),
        arguments.arch,
        reservation,
    );

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

async fn ensure_absent(host: &Host, name: &ContainerName) -> Result<()> {
    if exists(host, name).await? {
        bail!(
            "a container named `{name}` already exists; remove it with `cyber-sandbox rm {name}`"
        );
    }
    Ok(())
}

async fn exists(host: &Host, name: &ContainerName) -> Result<bool> {
    let containers = host
        .runtime()
        .list()
        .await
        .context("listing the runtime's containers")?;
    Ok(containers.iter().any(|container| &container.id == name))
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
