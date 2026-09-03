use std::{net::Ipv4Addr, path::PathBuf};

use cyber_sandbox_agents::SandboxEndpoint;
use cyber_sandbox_runtime::{Arch, ImageReference};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

/// What the host remembers about one sandbox between invocations.
///
/// The runtime is the authority on whether a container is running; this record holds the
/// facts the runtime does not keep, above all which host key reaches the sandbox and
/// which host directory its samples came from.
///
/// The sandbox's address is deliberately not among them. A machine is assigned one when
/// it starts and a different one the next time, so an address written here would be a
/// fact with an expiry date: every consumer asks the runtime for it instead, which is why
/// [`Self::endpoint`] cannot be built without one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxRecord {
    /// Identifier, which is also the container name and the agents' entry id.
    pub id: String,
    /// Image the sandbox was started from.
    pub image: ImageReference,
    /// Guest architecture.
    pub arch: Arch,
    /// Port sshd listens on inside the sandbox.
    pub ssh_port: u16,
    /// Account the agents log in as.
    pub researcher: String,
    /// Directory the agents start in inside the sandbox.
    pub work_dir: PathBuf,
    /// Host directory mounted read-only as the sample source, when one was given.
    pub samples: Option<PathBuf>,
    /// Private key the host authenticates with.
    pub identity_file: PathBuf,
    /// When the sandbox was last started.
    pub started_at: Timestamp,
}

impl SandboxRecord {
    /// The endpoint both agents are registered against.
    ///
    /// Takes the address rather than holding one: the agents' configuration files name a
    /// concrete host, so they have to be rewritten every time the sandbox starts, and
    /// requiring the caller to have just asked the runtime is what stops a stale address
    /// from being written into them.
    ///
    /// `known_hosts` is passed for the same reason the address is: it is derived from the
    /// host's state directory, which the record does not know about.
    #[must_use]
    pub fn endpoint(&self, address: Ipv4Addr, known_hosts: PathBuf) -> SandboxEndpoint {
        SandboxEndpoint {
            id: self.id.clone(),
            user: self.researcher.clone(),
            host: address.to_string(),
            port: self.ssh_port,
            identity_file: self.identity_file.clone(),
            known_hosts,
            start_directory: self.work_dir.clone(),
        }
    }
}
