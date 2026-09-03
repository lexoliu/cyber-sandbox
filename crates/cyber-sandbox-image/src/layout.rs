use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// A unix account the image creates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    /// Account name.
    pub name: String,
    /// Numeric user id.
    pub uid: u32,
    /// Numeric group id.
    pub gid: u32,
}

/// The fixed facts a sandbox image, its egress policy and the host CLI must all agree on.
///
/// Ports, uids and paths appear in the packet filter, in the gateway's own listeners and
/// in the host's audit reader. Holding them in one value that every renderer reads from
/// is what keeps them from drifting apart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxLayout {
    /// Account that runs sample code and the agents' tool side.
    pub researcher: Account,
    /// Account that runs the audit gateway.
    pub gateway: Account,
    /// Loopback port the transparent TCP proxy listens on.
    pub proxy_port: u16,
    /// Loopback port the intercepting DNS resolver listens on.
    pub dns_port: u16,
    /// Port sshd listens on inside the sandbox.
    pub ssh_port: u16,
    /// NFLOG group the packet filter reports refused traffic on.
    pub nflog_group: u16,
    /// Directory the gateway writes its audit trail into.
    pub audit_directory: PathBuf,
    /// Home directory of the gateway account, holding its generated CA.
    pub gateway_home: PathBuf,
    /// Authorized keys file for the researcher account.
    pub authorized_keys: PathBuf,
    /// Read-only mount point holding samples under analysis.
    pub samples_dir: PathBuf,
    /// Writable working directory for the researcher account.
    pub work_dir: PathBuf,
}

impl Default for SandboxLayout {
    fn default() -> Self {
        Self {
            researcher: Account {
                name: "researcher".to_owned(),
                uid: 1000,
                gid: 1000,
            },
            gateway: Account {
                name: "gateway".to_owned(),
                uid: 999,
                gid: 999,
            },
            proxy_port: 15000,
            dns_port: 15353,
            ssh_port: 22,
            nflog_group: 1,
            audit_directory: PathBuf::from("/var/log/cyber-sandbox"),
            gateway_home: PathBuf::from("/var/lib/cyber-sandbox"),
            authorized_keys: PathBuf::from("/etc/ssh/authorized_keys.d/researcher"),
            samples_dir: PathBuf::from("/samples"),
            work_dir: PathBuf::from("/work"),
        }
    }
}

/// File name of the JSONL audit trail inside [`SandboxLayout::audit_directory`].
pub const AUDIT_FILE_NAME: &str = "audit.jsonl";

/// File name of the gateway's MITM certificate authority inside its home directory.
pub const CA_FILE_NAME: &str = "gateway-ca.crt";

impl SandboxLayout {
    /// Full path of the audit trail inside the sandbox.
    #[must_use]
    pub fn audit_trail(&self) -> PathBuf {
        self.audit_directory.join(AUDIT_FILE_NAME)
    }

    /// Full path of the gateway's CA certificate inside the sandbox.
    #[must_use]
    pub fn ca_certificate(&self) -> PathBuf {
        self.gateway_home.join(CA_FILE_NAME)
    }

    /// Directory the audit trail lives in.
    #[must_use]
    pub fn audit_directory(&self) -> &Path {
        &self.audit_directory
    }
}
