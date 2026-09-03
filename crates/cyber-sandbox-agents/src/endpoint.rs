use std::path::PathBuf;

/// One sandbox as the host's agents should reach it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxEndpoint {
    /// Stable identifier, also the sandbox's name.
    pub id: String,
    /// Account the agents log in as.
    pub user: String,
    /// Address the sandbox listens on, as seen from the host.
    pub host: String,
    /// Port sshd listens on.
    pub port: u16,
    /// Private key the host authenticates with.
    pub identity_file: PathBuf,
    /// Directory the agents start in inside the sandbox.
    pub start_directory: PathBuf,
}

impl SandboxEndpoint {
    /// `user@host`, the form both agents' SSH invocations take.
    #[must_use]
    pub fn destination(&self) -> String {
        format!("{}@{}", self.user, self.host)
    }

    /// The `ssh` arguments that reach the sandbox without touching the host's agent socket.
    ///
    /// Agent forwarding stays off: the sandbox is the untrusted side, and an agent socket
    /// reaching into it would undo the reason the credentials stay on the host.
    #[must_use]
    pub fn ssh_arguments(&self) -> Vec<String> {
        vec![
            "-p".to_owned(),
            self.port.to_string(),
            "-i".to_owned(),
            self.identity_file.display().to_string(),
            "-o".to_owned(),
            "ForwardAgent=no".to_owned(),
            "-o".to_owned(),
            "StrictHostKeyChecking=accept-new".to_owned(),
            self.destination(),
        ]
    }
}
