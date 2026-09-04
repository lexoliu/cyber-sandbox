//! The Claude Code state a session starts with, so that opening one is not a wizard.
//!
//! Claude Code asks a first-run question about the theme, another about trusting the
//! directory it was started in, and a third about running without approvals. Every one of
//! them is a question about a machine cyber-sandbox made seconds earlier, on behalf of a
//! researcher who asked for exactly that machine — and a session that begins by asking
//! them is one nobody can hand to an agent and walk away from, which is the whole point of
//! running it in a sandbox.
//!
//! The answers are therefore written into the image, in the two files Claude Code itself
//! keeps them in. Nothing here decides anything about permissions inside the session that
//! the sandbox does not already decide by being a sandbox.

use serde::Serialize;
use std::collections::BTreeMap;

use crate::layout::SandboxLayout;

/// Colour scheme a session's Claude Code starts in.
///
/// The terminal it is displayed in belongs to the host, so this cannot be right for
/// everyone; it is the answer the first-run picker offers first, and `/theme` changes it.
const THEME: &str = "dark";

/// `~/.claude.json`: the researcher account's Claude Code configuration.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Configuration {
    has_completed_onboarding: bool,
    projects: BTreeMap<String, Project>,
}

/// One directory's entry in that configuration.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Project {
    has_trust_dialog_accepted: bool,
}

/// `~/.claude/settings.json`: the settings that are not per-directory.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    theme: &'static str,
    skip_dangerous_mode_permission_prompt: bool,
}

impl Configuration {
    /// The configuration a session's researcher account is given.
    ///
    /// The working directory is trusted because the researcher asked for the session it
    /// belongs to, and it is the only directory an agent is ever started in here.
    #[must_use]
    pub fn for_layout(layout: &SandboxLayout) -> Self {
        Self {
            has_completed_onboarding: true,
            projects: BTreeMap::from([(
                layout.work_dir.display().to_string(),
                Project {
                    has_trust_dialog_accepted: true,
                },
            )]),
        }
    }
}

impl Settings {
    /// The settings a session's researcher account is given.
    ///
    /// Approvals are off because the session is the sandbox: an agent that stops to ask
    /// for permission to read a file inside a machine built to contain it is one a
    /// researcher has to babysit for no gain.
    #[must_use]
    pub fn new() -> Self {
        Self {
            theme: THEME,
            skip_dangerous_mode_permission_prompt: true,
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self::new()
    }
}
