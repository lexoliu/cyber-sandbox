use askama::Template;

use crate::{layout::SandboxLayout, profile::ToolProfile};

/// The image definition itself.
#[derive(Debug, Template)]
#[template(path = "Dockerfile", escape = "none")]
pub struct Dockerfile {
    /// Kali image the sandbox derives from.
    pub base_image: String,
    /// Packages to install.
    pub packages: Vec<String>,
    /// Researcher account name.
    pub researcher_user: String,
    /// Researcher uid.
    pub researcher_uid: u32,
    /// Researcher gid.
    pub researcher_gid: u32,
    /// Gateway account name.
    pub gateway_user: String,
    /// Gateway uid.
    pub gateway_uid: u32,
    /// Gateway gid.
    pub gateway_gid: u32,
    /// Home directory created for the gateway account.
    pub gateway_home: String,
    /// Directory the audit trail is written into.
    pub audit_directory: String,
    /// Read-only mount point holding samples under analysis.
    pub samples_dir: String,
    /// Writable working directory for the researcher account.
    pub work_dir: String,
    /// npm packages providing the agents' in-sandbox tool side.
    pub agent_packages: String,
}

/// The packet filter policy applied before `CAP_NET_ADMIN` is dropped.
#[derive(Debug, Template)]
#[template(path = "egress-policy.sh", escape = "none")]
pub struct EgressPolicy {
    /// Gateway uid, exempted from redirection.
    pub gateway_uid: u32,
    /// Transparent proxy port.
    pub proxy_port: u16,
    /// Intercepting resolver port.
    pub dns_port: u16,
    /// Port sshd listens on.
    pub ssh_port: u16,
    /// NFLOG group refused packets are reported on.
    pub nflog_group: u16,
}

/// The container's init script.
#[derive(Debug, Template)]
#[template(path = "entrypoint.sh", escape = "none")]
pub struct Entrypoint {
    /// Gateway account name.
    pub gateway_user: String,
    /// Audit trail path.
    pub audit_trail: String,
    /// Gateway CA certificate path.
    pub ca_certificate: String,
    /// Authorized keys file the entrypoint writes the host's public key into.
    pub authorized_keys: String,
    /// Transparent proxy port.
    pub proxy_port: u16,
    /// Intercepting resolver port.
    pub dns_port: u16,
    /// NFLOG group refused packets are reported on.
    pub nflog_group: u16,
}

/// The sshd drop-in that exposes the agent control plane and nothing else.
#[derive(Debug, Template)]
#[template(path = "sshd_config", escape = "none")]
pub struct SshdConfig {
    /// Port sshd listens on.
    pub ssh_port: u16,
    /// Authorized keys file for the researcher account.
    pub authorized_keys: String,
    /// Researcher account name.
    pub researcher_user: String,
}

/// Every generated file that makes up the image build context.
#[derive(Debug)]
pub struct RenderedImage {
    /// Contents of `Dockerfile`.
    pub dockerfile: String,
    /// Contents of `entrypoint.sh`.
    pub entrypoint: String,
    /// Contents of `egress-policy.sh`.
    pub egress_policy: String,
    /// Contents of `sshd_config`.
    pub sshd_config: String,
}

impl RenderedImage {
    /// Renders every generated file from one layout and profile.
    ///
    /// # Errors
    /// Fails only when a template is malformed, which the compiler already rejects, or
    /// when rendering runs out of memory.
    pub fn render(
        base_image: &str,
        profile: ToolProfile,
        layout: &SandboxLayout,
    ) -> Result<Self, askama::Error> {
        let dockerfile = Dockerfile {
            base_image: base_image.to_owned(),
            packages: profile.packages(),
            researcher_user: layout.researcher.name.clone(),
            researcher_uid: layout.researcher.uid,
            researcher_gid: layout.researcher.gid,
            gateway_user: layout.gateway.name.clone(),
            gateway_uid: layout.gateway.uid,
            gateway_gid: layout.gateway.gid,
            gateway_home: layout.gateway_home.display().to_string(),
            audit_directory: layout.audit_directory().display().to_string(),
            samples_dir: layout.samples_dir.display().to_string(),
            work_dir: layout.work_dir.display().to_string(),
            agent_packages: crate::profile::AGENT_PACKAGES.join(" "),
        }
        .render()?;
        let egress_policy = EgressPolicy {
            gateway_uid: layout.gateway.uid,
            proxy_port: layout.proxy_port,
            dns_port: layout.dns_port,
            ssh_port: layout.ssh_port,
            nflog_group: layout.nflog_group,
        }
        .render()?;
        let entrypoint = Entrypoint {
            gateway_user: layout.gateway.name.clone(),
            audit_trail: layout.audit_trail().display().to_string(),
            ca_certificate: layout.ca_certificate().display().to_string(),
            authorized_keys: layout.authorized_keys.display().to_string(),
            proxy_port: layout.proxy_port,
            dns_port: layout.dns_port,
            nflog_group: layout.nflog_group,
        }
        .render()?;
        let sshd_config = SshdConfig {
            ssh_port: layout.ssh_port,
            authorized_keys: layout.authorized_keys.display().to_string(),
            researcher_user: layout.researcher.name.clone(),
        }
        .render()?;
        Ok(Self {
            dockerfile,
            entrypoint,
            egress_policy,
            sshd_config,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered() -> RenderedImage {
        RenderedImage::render(
            "docker.io/kalilinux/kali-rolling:latest",
            ToolProfile::Core,
            &SandboxLayout::default(),
        )
        .unwrap()
    }

    #[test]
    fn the_gateway_uid_is_the_only_uid_exempt_from_redirection() {
        let policy = rendered().egress_policy;
        assert!(policy.contains("readonly GATEWAY_UID=999"));
        assert!(policy.contains("--uid-owner \"${GATEWAY_UID}\" -j RETURN"));
    }

    #[test]
    fn every_output_chain_defaults_to_drop() {
        let policy = rendered().egress_policy;
        for chain in ["iptables -P OUTPUT DROP", "ip6tables -P OUTPUT DROP"] {
            assert!(policy.contains(chain), "missing default drop: {chain}");
        }
    }

    #[test]
    fn nothing_but_the_gateway_and_loopback_is_accepted_on_the_way_out() {
        let policy = rendered().egress_policy;
        let accepts: Vec<&str> = policy
            .lines()
            .filter(|line| line.starts_with("iptables -A OUTPUT") && line.ends_with("-j ACCEPT"))
            .collect();
        assert_eq!(
            accepts,
            vec![
                "iptables -A OUTPUT -o lo -j ACCEPT",
                "iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                "iptables -A OUTPUT -m owner --uid-owner \"${GATEWAY_UID}\" -j ACCEPT",
            ],
            "an accept matched by protocol rather than by uid or interface would let \
             traffic the redirection missed leave unaudited"
        );
    }

    #[test]
    fn the_entrypoint_drops_net_admin_before_running_anything_untrusted() {
        let entrypoint = rendered().entrypoint;
        let policy_at = entrypoint.find("egress-policy.sh").unwrap();
        let drop_at = entrypoint.find("capsh --drop=cap_net_admin").unwrap();
        let sshd_at = entrypoint.find("/usr/sbin/sshd").unwrap();
        assert!(
            policy_at < drop_at && drop_at < sshd_at,
            "the policy must be installed, then NET_ADMIN dropped, then sshd started"
        );
    }

    #[test]
    fn the_host_public_key_is_installed_by_root_before_sshd_starts() {
        let entrypoint = rendered().entrypoint;
        let write_at = entrypoint
            .find("printf '%s\\n' \"${CYBER_SANDBOX_AUTHORIZED_KEY}\"")
            .unwrap();
        let sshd_at = entrypoint.find("/usr/sbin/sshd").unwrap();
        assert!(write_at < sshd_at);
        assert!(
            entrypoint.contains("readonly AUTHORIZED_KEYS=/etc/ssh/authorized_keys.d/researcher"),
            "{entrypoint}"
        );
    }

    #[test]
    fn the_authority_is_installed_before_the_gateway_starts_serving() {
        let entrypoint = rendered().entrypoint;
        let init_at = entrypoint.find("init-ca").unwrap();
        let install_at = entrypoint.find("update-ca-certificates").unwrap();
        let serve_at = entrypoint.find("serve \\").unwrap();
        assert!(
            init_at < install_at && install_at < serve_at,
            "the trust store must hold the authority before any traffic can flow"
        );
    }

    #[test]
    fn only_the_gateway_account_can_execute_the_binary_that_carries_a_capability() {
        let dockerfile = rendered().dockerfile;
        assert!(
            dockerfile.contains("setcap cap_net_admin+ep /usr/local/bin/cyber-sandbox-gateway")
        );
        assert!(dockerfile.contains("chmod 0050 /usr/local/bin/cyber-sandbox-gateway"));
        assert!(
            dockerfile.contains("chown root:gateway /usr/local/bin/cyber-sandbox-gateway"),
            "{dockerfile}"
        );
    }

    #[test]
    fn the_headless_profile_adds_the_kali_metapackage() {
        assert!(
            ToolProfile::Headless
                .packages()
                .contains(&"kali-linux-headless".to_owned())
        );
        assert!(
            !ToolProfile::Core
                .packages()
                .contains(&"kali-linux-headless".to_owned())
        );
    }

    #[test]
    fn sshd_permits_only_remote_stream_local_forwarding() {
        let config = rendered().sshd_config;
        assert!(config.contains("AllowStreamLocalForwarding remote"));
        assert!(config.contains("AllowTcpForwarding no"));
        assert!(config.contains("PermitRootLogin no"));
        assert!(config.contains("PasswordAuthentication no"));
    }
}
