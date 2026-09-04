//! Renders the cyber-sandbox analysis image and the scripts that enforce its egress
//! policy.
//!
//! The Dockerfile, the entrypoint, the packet-filter policy and the sshd drop-in are all
//! compiled templates fed from a single [`SandboxLayout`], so a port or uid that changes
//! in one place cannot silently disagree with another.

mod layout;
mod onboarding;
mod openssh;
mod profile;
mod render;
mod stage;

pub use layout::{Account, SandboxLayout};
pub use openssh::OpenSshBuild;
pub use profile::{ToolProfile, UnknownProfile};
pub use render::RenderedImage;
pub use stage::{BuildContext, StageError};
