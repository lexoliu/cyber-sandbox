use std::path::PathBuf;

/// Failures while editing the host's agent configuration.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// A configuration file could not be read or written.
    #[error("failed to access {path}")]
    Io {
        /// File involved.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },
    /// Claude Code's settings are not the JSON object they must be.
    #[error("{path} is not a JSON object")]
    NotAnObject {
        /// File involved.
        path: PathBuf,
    },
    /// Claude Code's settings could not be parsed.
    #[error("failed to parse {path} as JSON")]
    Json {
        /// File involved.
        path: PathBuf,
        /// Underlying parse error.
        #[source]
        source: serde_json::Error,
    },
    /// A configuration key the sandbox owns is present but holds the wrong kind of value.
    ///
    /// Overwriting it would destroy hand-written configuration, so registration stops.
    #[error("{key} in {path} is not the shape cyber-sandbox expects")]
    UnexpectedShape {
        /// File involved.
        path: PathBuf,
        /// Key involved.
        key: &'static str,
    },
    /// Codex's environments file could not be parsed.
    #[error("failed to parse {path} as TOML")]
    Toml {
        /// File involved.
        path: PathBuf,
        /// Underlying parse error.
        #[source]
        source: toml_edit::TomlError,
    },
}
