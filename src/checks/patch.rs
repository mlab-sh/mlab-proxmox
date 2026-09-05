//! Patch state: what is installed, where updates would come from, and whether
//! they can arrive at all.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::checks::{flag, s, Finding, Severity};
use crate::collect::Node;

pub fn all(nodes: &[Node]) -> Vec<Finding> {
    let mut out = Vec::new();
    for n in nodes {
        out.extend(node(n));
    }
    out.extend(skew(nodes));
    out
}

fn node(n: &Node) -> Vec<Finding> {
    let mut out = Vec::new();
    let subject = format!("node/{}", n.name);

    // ---- where updates come from -------------------------------------------
    let mut enterprise = false;
    let mut no_subscription = false;
    let mut test = false;
    let mut third_party: Vec<String> = Vec::new();

    if let Some(files) = n.repositories.get("files").and_then(Value::as_array) {
        for f in files {
            let path = s(f, "path");
            let Some(repos) = f.get("repositories").and_then(Value::as_array) else {
                continue;
            };
            for r in repos {
                if !flag(r, "Enabled", true) {
                    continue;
                }
                let uris = r
                    .get("URIs")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>()
                            .join(" ")
                    })
                    .unwrap_or_default();
                let comps = r
                    .get("Components")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>()
                            .join(" ")
                    })
                    .unwrap_or_default();

                if uris.contains("enterprise.proxmox.com") {
                    enterprise = true;
                } else if comps.split_whitespace().any(|c| c == "pve-no-subscription")
                    || comps.split_whitespace().any(|c| c == "pbs-no-subscription")
                {
                    no_subscription = true;
                } else if comps.split_whitespace().any(|c| c.ends_with("test")) {
                    test = true;
                } else if !uris.contains("debian.org") && !uris.contains("proxmox.com") {
                    third_party.push(format!(
                        "{uris} ({})",
                        path.rsplit('/').next().unwrap_or("")
                    ));
                }
            }
        }
    }

    let sub_status = s(&n.subscription, "status");
    let active = sub_status.eq_ignore_ascii_case("active");

    if enterprise && !active {
        out.push(
            Finding::new(
                "patch.enterprise-without-subscription",
                Severity::High,
                &subject,
                "the enterprise repository is enabled without a subscription",
            )
            .detail(format!(
                "Subscription status is {}. Every `apt update` fails with 401 and no security \
                 update ever lands.",
                if sub_status.is_empty() {
                    "unknown"
                } else {
                    &sub_status
                }
            ))
            .remedy(
                "Either buy a subscription, or switch the node to the no-subscription repository.",
            ),
        );
    }
    if !enterprise && !no_subscription && !test {
        out.push(
            Finding::new(
                "patch.no-proxmox-repository",
                Severity::High,
                &subject,
                "no Proxmox repository is enabled",
            )
            .detail("Nothing on this node will ever receive a Proxmox update."),
        );
    }
    if test {
        out.push(
            Finding::new(
                "patch.test-repository",
                Severity::Medium,
                &subject,
                "a test repository is enabled",
            )
            .detail("Test packages are not meant for a machine anybody depends on."),
        );
    }
    for t in third_party {
        out.push(
            Finding::new(
                "patch.third-party-repository",
                Severity::Low,
                &subject,
                "a third-party APT repository is enabled",
            )
            .detail(format!(
                "{t} — its maintainer can install anything on this host at the next upgrade."
            )),
        );
    }
    if let Some(errors) = n.repositories.get("errors").and_then(Value::as_array) {
        for e in errors {
            out.push(
                Finding::new(
                    "patch.repository-error",
                    Severity::Medium,
                    &subject,
                    "a repository file does not parse",
                )
                .detail(s(e, "error")),
            );
        }
    }

    if !active && !sub_status.is_empty() {
        out.push(
            Finding::new(
                "patch.no-subscription",
                Severity::Info,
                &subject,
                format!("subscription status is {sub_status}"),
            )
            .detail(s(&n.subscription, "message")),
        );
    }

    // ---- what is waiting ----------------------------------------------------
    match &n.updates {
        None => out.push(
            Finding::new(
                "patch.updates-unreadable",
                Severity::Unreadable,
                &subject,
                "the pending update list cannot be read",
            )
            .detail(
                "`GET /nodes/{node}/apt/update` needs `Sys.Modify`, which also rewrites host \
                 network configuration. Nothing is claimed here about how patched this node is.",
            )
            .remedy("Grant Sys.Modify on the node if you accept that trade, or check with `pveversion -v` over SSH."),
        ),
        Some(list) if list.is_empty() => {}
        Some(list) => {
            let security: Vec<String> = list
                .iter()
                .filter(|p| {
                    let origin = s(p, "Origin");
                    origin.contains("Security") || s(p, "Section").contains("security")
                })
                .map(|p| s(p, "Package"))
                .collect();
            let severity = if security.is_empty() {
                Severity::Low
            } else {
                Severity::High
            };
            out.push(
                Finding::new(
                    "patch.updates-pending",
                    severity,
                    &subject,
                    format!("{} package update(s) waiting", list.len()),
                )
                .detail(if security.is_empty() {
                    list.iter()
                        .map(|p| s(p, "Package"))
                        .take(12)
                        .collect::<Vec<_>>()
                        .join(", ")
                } else {
                    format!("{} of them are security updates: {}", security.len(), security.join(", "))
                }),
            );
        }
    }

    // ---- the kernel that is actually running --------------------------------
    // `apt/versions` needs no privilege beyond the audit role, so the one
    // question `apt/update` was hiding — is a reboot owed — is answerable.
    let running = n
        .status
        .get("current-kernel")
        .and_then(|k| k.get("release"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let booted = n
        .status
        .get("boot-info")
        .and_then(|b| b.get("mode"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !running.is_empty() && !booted.is_empty() {
        out.push(Finding::new(
            "patch.kernel",
            Severity::Info,
            &subject,
            format!("running kernel {running}, booted in {booted} mode"),
        ));
    }

    if let Some(newer) = newer_kernel(n, &running) {
        out.push(
            Finding::new(
                "patch.reboot-required",
                Severity::High,
                &subject,
                format!("kernel {newer} is installed and {running} is running"),
            )
            .detail(
                "Every fix in the installed kernel — including the ones that closed a local \
                 privilege escalation — takes effect at the next boot and not before.",
            ),
        );
    }

    // A subscription that lapses takes the enterprise repository with it.
    let due = s(&n.subscription, "nextduedate");
    if active && !due.is_empty() {
        out.push(Finding::new(
            "patch.subscription-due",
            Severity::Info,
            &subject,
            format!("the subscription runs to {due}"),
        ));
    }

    out
}

/// An installed Proxmox kernel newer than the one currently booted.
///
/// The package list carries `proxmox-kernel-6.14.11-4-pve` style names; the
/// running release is `6.14.11-4-pve`. Comparing the version fields of the two
/// avoids parsing either as a number, which is how this goes wrong.
fn newer_kernel(n: &Node, running: &str) -> Option<String> {
    if running.is_empty() {
        return None;
    }
    let mut best: Option<String> = None;
    for p in &n.packages {
        let name = s(p, "Package");
        // The metapackage carries no release of its own; the versioned ones do.
        let Some(rest) = name.strip_prefix("proxmox-kernel-") else {
            continue;
        };
        if !rest.ends_with("-pve") && !rest.ends_with("-pve-signed") {
            continue;
        }
        if s(p, "CurrentState") != "Installed" {
            continue;
        }
        let release = rest.trim_end_matches("-signed").to_string();
        if version_gt(&release, running) {
            best = match best {
                Some(b) if version_gt(&b, &release) => Some(b),
                _ => Some(release),
            };
        }
    }
    best
}

/// Compare two kernel releases field by field, numerically where both fields
/// are numbers and lexically otherwise.
fn version_gt(a: &str, b: &str) -> bool {
    let split = |v: &str| -> Vec<String> { v.split(['.', '-']).map(str::to_string).collect() };
    let (x, y) = (split(a), split(b));
    for i in 0..x.len().max(y.len()) {
        let (l, r) = (x.get(i), y.get(i));
        match (l, r) {
            (Some(l), Some(r)) => match (l.parse::<u64>(), r.parse::<u64>()) {
                (Ok(l), Ok(r)) if l != r => return l > r,
                (Ok(_), Ok(_)) => continue,
                _ if l != r => return l > r,
                _ => continue,
            },
            (Some(_), None) => return true,
            (None, Some(_)) => return false,
            (None, None) => break,
        }
    }
    false
}

/// Nodes of one cluster running different builds.
fn skew(nodes: &[Node]) -> Vec<Finding> {
    if nodes.len() < 2 {
        return Vec::new();
    }
    let versions: BTreeSet<String> = nodes
        .iter()
        .map(|n| s(&n.version, "version"))
        .filter(|v| !v.is_empty())
        .collect();
    if versions.len() < 2 {
        return Vec::new();
    }
    let detail = nodes
        .iter()
        .map(|n| format!("{}: {}", n.name, s(&n.version, "version")))
        .collect::<Vec<_>>()
        .join(", ");
    vec![Finding::new(
        "patch.version-skew",
        Severity::Medium,
        "cluster",
        format!(
            "{} different Proxmox versions across the cluster",
            versions.len()
        ),
    )
    .detail(detail)
    .remedy("Proxmox supports a mixed cluster only for the length of an upgrade.")]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn node_with(repos: Value, subscription: Value, updates: Option<Vec<Value>>) -> Node {
        Node {
            name: "n1".into(),
            status: Value::Null,
            version: json!({ "version": "9.1.1" }),
            subscription,
            services: vec![],
            network: vec![],
            dns: Value::Null,
            time: Value::Null,
            certificates: vec![],
            repositories: repos,
            disks: vec![],
            pci: vec![],
            thin_pools: vec![],
            zfs_pools: vec![],
            hosts: Value::Null,
            firewall: Value::Null,
            firewall_rules: vec![],
            updates,
            packages: vec![],
        }
    }

    fn repo(uri: &str, component: &str, enabled: bool) -> Value {
        json!({
            "files": [{
                "path": "/etc/apt/sources.list.d/pve.list",
                "repositories": [{
                    "URIs": [uri], "Components": [component], "Enabled": enabled
                }]
            }],
            "errors": []
        })
    }

    #[test]
    fn the_enterprise_repository_without_a_subscription_breaks_every_update() {
        let n = node_with(
            repo(
                "https://enterprise.proxmox.com/debian/pve",
                "pve-enterprise",
                true,
            ),
            json!({ "status": "notfound" }),
            None,
        );
        let out = node(&n);
        assert!(out.iter().any(
            |f| f.id == "patch.enterprise-without-subscription" && f.severity == Severity::High
        ));
    }

    #[test]
    fn the_no_subscription_repository_alone_is_a_supported_setup() {
        let n = node_with(
            repo(
                "http://download.proxmox.com/debian/pve",
                "pve-no-subscription",
                true,
            ),
            json!({ "status": "notfound", "message": "no subscription" }),
            Some(vec![]),
        );
        let out = node(&n);
        assert!(!out.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn a_security_update_outranks_an_ordinary_one() {
        let n = node_with(
            repo(
                "http://download.proxmox.com/debian/pve",
                "pve-no-subscription",
                true,
            ),
            json!({ "status": "active" }),
            Some(vec![
                json!({ "Package": "openssl", "Origin": "Debian:Debian-Security" }),
            ]),
        );
        let out = node(&n);
        let f = out
            .iter()
            .find(|f| f.id == "patch.updates-pending")
            .unwrap();
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn an_unreadable_update_list_admits_it_rather_than_passing() {
        let n = node_with(
            repo(
                "http://download.proxmox.com/debian/pve",
                "pve-no-subscription",
                true,
            ),
            json!({ "status": "active" }),
            None,
        );
        let out = node(&n);
        let f = out
            .iter()
            .find(|f| f.id == "patch.updates-unreadable")
            .unwrap();
        assert_eq!(f.severity, Severity::Unreadable);
    }

    #[test]
    fn a_newer_installed_kernel_means_a_reboot_is_owed() {
        let mut n = node_with(
            repo(
                "http://download.proxmox.com/debian/pve",
                "pve-no-subscription",
                true,
            ),
            json!({ "status": "active" }),
            Some(vec![]),
        );
        n.status = json!({ "current-kernel": { "release": "6.14.11-2-pve" } });
        n.packages = vec![
            json!({ "Package": "proxmox-kernel-6.14.11-4-pve-signed", "CurrentState": "Installed" }),
            json!({ "Package": "proxmox-kernel-6.14", "CurrentState": "Installed" }),
        ];
        assert_eq!(
            newer_kernel(&n, "6.14.11-2-pve").as_deref(),
            Some("6.14.11-4-pve")
        );
        assert!(node(&n).iter().any(|f| f.id == "patch.reboot-required"));
    }

    #[test]
    fn running_the_newest_installed_kernel_owes_nothing() {
        let mut n = node_with(
            repo(
                "http://download.proxmox.com/debian/pve",
                "pve-no-subscription",
                true,
            ),
            json!({ "status": "active" }),
            Some(vec![]),
        );
        n.packages = vec![json!({
            "Package": "proxmox-kernel-6.17.2-1-pve-signed", "CurrentState": "Installed"
        })];
        assert_eq!(newer_kernel(&n, "6.17.2-1-pve"), None);
    }

    #[test]
    fn kernel_releases_compare_field_by_field_and_not_as_text() {
        assert!(version_gt("6.14.11-4-pve", "6.14.11-2-pve"));
        assert!(
            version_gt("6.17.2-1-pve", "6.9.10-1-pve"),
            "9 < 17 numerically"
        );
        assert!(!version_gt("6.14.11-2-pve", "6.14.11-4-pve"));
        assert!(!version_gt("6.14.11-2-pve", "6.14.11-2-pve"));
    }
}
