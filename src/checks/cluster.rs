//! Cluster integrity: quorum, corosync, migration, HA and replication.

use serde_json::Value;

use crate::checks::{flag, i, prop, propstring, s, Finding, Severity};

pub fn all(
    status: &[Value],
    totem: &Value,
    options: &Value,
    ha: &[Value],
    replication: &[Value],
    qdevice: &Value,
    ha_status: &[Value],
) -> Vec<Finding> {
    let mut out = Vec::new();
    out.extend(quorum(status, qdevice));
    out.extend(ha_state(ha_status));
    out.extend(corosync(totem, status));
    out.extend(datacenter(options));
    out.extend(ha_and_replication(ha, replication));
    out
}

fn quorum(status: &[Value], qdevice: &Value) -> Vec<Finding> {
    let mut out = Vec::new();
    let nodes: Vec<&Value> = status.iter().filter(|r| s(r, "type") == "node").collect();
    let cluster = status.iter().find(|r| s(r, "type") == "cluster");

    let Some(c) = cluster else {
        out.push(
            Finding::new(
                "cluster.standalone",
                Severity::Info,
                "cluster",
                "this is a standalone node, not a cluster",
            )
            .detail(
                "No corosync, no quorum, no HA. Everything below about cluster integrity is \
                 simply not applicable.",
            ),
        );
        return out;
    };

    if i(c, "quorate") != Some(1) {
        out.push(
            Finding::new(
                "cluster.no-quorum",
                Severity::Critical,
                "cluster",
                "the cluster has lost quorum",
            )
            .detail(
                "pmxcfs is read-only until quorum returns: no guest starts, no configuration \
                 change lands, HA cannot recover anything.",
            ),
        );
    }

    let offline: Vec<String> = nodes
        .iter()
        .filter(|n| i(n, "online") != Some(1))
        .map(|n| s(n, "name"))
        .collect();
    if !offline.is_empty() {
        out.push(
            Finding::new(
                "cluster.node-offline",
                Severity::High,
                "cluster",
                format!("{} node(s) are offline", offline.len()),
            )
            .detail(offline.join(", ")),
        );
    }

    // An even member count wastes a node: the cluster tolerates the same number
    // of failures as one node fewer, and a clean split has no majority.
    // A QDevice is the third vote that makes an even membership work, so
    // reading the configuration is what keeps this from being a false alarm.
    let has_qdevice = qdevice.as_object().map(|o| !o.is_empty()).unwrap_or(false);
    let total = nodes.len();
    if total >= 2 && total.is_multiple_of(2) && !has_qdevice {
        out.push(
            Finding::new(
                "cluster.even-membership",
                Severity::Medium,
                "cluster",
                format!("{total} nodes and no tie-breaker"),
            )
            .detail(
                "An even membership survives no more failures than an odd one below it, and a \
                 clean split leaves neither half quorate.",
            )
            .remedy("Add a QDevice, or a node."),
        );
    }
    out
}

/// What the HA manager currently thinks, rather than what is configured.
fn ha_state(ha_status: &[Value]) -> Vec<Finding> {
    let mut out = Vec::new();
    for row in ha_status {
        let id = s(row, "id");
        // The manager reports its own quorum row alongside the resources.
        let state = s(row, "state");
        let status = s(row, "status");

        if matches!(state.as_str(), "error" | "fence") {
            out.push(
                Finding::new(
                    "cluster.ha-resource-error",
                    Severity::High,
                    format!("ha/{}", s(row, "sid")),
                    format!("{} is in state {state}", s(row, "sid")),
                )
                .detail(if state == "fence" {
                    "A node is being fenced: HA is recovering the resource somewhere else."
                } else {
                    "HA gave up on this resource and will not restart it until someone clears it."
                }),
            );
        }

        if id == "quorum" && !status.is_empty() && status != "OK" {
            out.push(Finding::new(
                "cluster.ha-no-quorum",
                Severity::Critical,
                "cluster",
                format!("the HA manager reports quorum as {status}"),
            ));
        }
    }
    out
}

fn corosync(totem: &Value, status: &[Value]) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(t) = totem.as_object() else {
        return out;
    };
    let nodes = status.iter().filter(|r| s(r, "type") == "node").count();
    if nodes < 2 {
        return out;
    }

    // Corosync links are `interface` entries; one of them is a single point of
    // failure for the whole cluster.
    let links = t
        .keys()
        .filter(|k| k.starts_with("interface"))
        .count()
        .max(usize::from(t.contains_key("interface")));
    if links <= 1 {
        out.push(
            Finding::new(
                "cluster.single-corosync-link",
                Severity::Medium,
                "cluster",
                "corosync runs on a single link",
            )
            .detail(
                "Any interruption on that network — a switch reboot, a saturated uplink — costs \
                 quorum and stops every guest that depends on it.",
            )
            .remedy(
                "Add a second link on a separate physical path (Datacenter → Cluster → corosync).",
            ),
        );
    }

    if s(&Value::Object(t.clone()), "secauth") == "off"
        || s(&Value::Object(t.clone()), "crypto_cipher") == "none"
    {
        out.push(
            Finding::new(
                "cluster.corosync-unencrypted",
                Severity::High,
                "cluster",
                "corosync traffic is neither encrypted nor authenticated",
            )
            .detail("Anyone on that segment can read cluster state, and forge it."),
        );
    }
    out
}

fn datacenter(options: &Value) -> Vec<Finding> {
    let mut out = Vec::new();

    let migration = s(options, "migration");
    if migration.contains("insecure") || flag(options, "migration_unsecure", false) {
        out.push(
            Finding::new(
                "cluster.insecure-migration",
                Severity::High,
                "cluster",
                "live migration runs unencrypted",
            )
            .detail(
                "Guest memory, and everything in it, crosses the migration network in the clear.",
            )
            .remedy("Datacenter → Options → Migration Settings → type: secure."),
        );
    }

    let proxy = s(options, "http_proxy");
    if proxy.contains('@') {
        out.push(
            Finding::new(
                "cluster.proxy-credentials",
                Severity::High,
                "cluster",
                "the HTTP proxy URL contains credentials",
            )
            .detail(
                "`http_proxy` in datacenter.cfg carries a username and password in clear text, \
                 readable by anyone with Sys.Audit.",
            ),
        );
    }

    // The MAC prefix decides whether two clusters on one L2 can collide.
    let prefix = s(options, "mac_prefix");
    if !prefix.is_empty() && prefix != "BC:24:11" {
        out.push(Finding::new(
            "cluster.custom-mac-prefix",
            Severity::Info,
            "cluster",
            format!("guest MAC addresses use the {prefix} prefix"),
        ));
    }

    if let Some(ha) = options.get("ha") {
        let p = propstring(&s(&serde_json::json!({ "v": ha }), "v"), "");
        if let Some(policy) = prop(&p, "shutdown_policy") {
            if policy == "freeze" {
                out.push(Finding::new(
                    "cluster.ha-shutdown-freeze",
                    Severity::Info,
                    "cluster",
                    "HA resources freeze on shutdown rather than migrating",
                ));
            }
        }
    }
    out
}

fn ha_and_replication(ha: &[Value], replication: &[Value]) -> Vec<Finding> {
    let mut out = Vec::new();

    for r in ha {
        if s(r, "state") == "disabled" {
            out.push(
                Finding::new(
                    "cluster.ha-resource-disabled",
                    Severity::Low,
                    format!("ha/{}", s(r, "sid")),
                    format!("{} is registered with HA but disabled", s(r, "sid")),
                )
                .detail("HA will not restart it anywhere."),
            );
        }
    }

    for j in replication {
        if flag(j, "disable", false) {
            out.push(
                Finding::new(
                    "cluster.replication-disabled",
                    Severity::Medium,
                    format!("replication/{}", s(j, "id")),
                    format!("replication job {} is disabled", s(j, "id")),
                )
                .detail(format!(
                    "Guest {} no longer replicates to {}; a failover would start from stale data.",
                    s(j, "guest"),
                    s(j, "target")
                )),
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_standalone_node_says_so_instead_of_failing_cluster_checks() {
        let status = vec![json!({ "type": "node", "name": "pve1", "online": 1, "local": 1 })];
        let out = quorum(&status, &Value::Null);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "cluster.standalone");
    }

    #[test]
    fn losing_quorum_is_the_worst_thing_a_cluster_can_report() {
        let status = vec![
            json!({ "type": "cluster", "name": "lab", "quorate": 0, "nodes": 2 }),
            json!({ "type": "node", "name": "a", "online": 1 }),
            json!({ "type": "node", "name": "b", "online": 0 }),
        ];
        let out = quorum(&status, &Value::Null);
        assert!(out
            .iter()
            .any(|f| f.id == "cluster.no-quorum" && f.severity == Severity::Critical));
        assert!(out.iter().any(|f| f.id == "cluster.node-offline"));
        assert!(out.iter().any(|f| f.id == "cluster.even-membership"));
    }

    #[test]
    fn a_qdevice_is_the_tie_breaker_an_even_cluster_is_missing() {
        let status = vec![
            json!({ "type": "cluster", "name": "lab", "quorate": 1, "nodes": 2 }),
            json!({ "type": "node", "name": "a", "online": 1 }),
            json!({ "type": "node", "name": "b", "online": 1 }),
        ];
        assert!(quorum(&status, &json!({}))
            .iter()
            .any(|f| f.id == "cluster.even-membership"));
        // With one configured, the same cluster is fine and must stay quiet.
        assert!(!quorum(&status, &json!({ "QDevice": { "votes": "1" } }))
            .iter()
            .any(|f| f.id == "cluster.even-membership"));
    }

    #[test]
    fn a_resource_ha_gave_up_on_is_high_and_a_fence_says_so() {
        let out = ha_state(&[json!({ "id": "service:vm:100", "sid": "vm:100", "state": "error" })]);
        assert_eq!(out[0].severity, Severity::High);
        let out = ha_state(&[json!({ "id": "service:vm:100", "sid": "vm:100", "state": "fence" })]);
        assert!(out[0].detail.contains("fenced"));
    }

    #[test]
    fn insecure_migration_is_flagged_in_both_spellings() {
        assert!(!datacenter(&json!({ "migration": "type=insecure" })).is_empty());
        assert!(!datacenter(&json!({ "migration_unsecure": 1 })).is_empty());
        assert!(datacenter(&json!({ "migration": "type=secure" })).is_empty());
    }

    #[test]
    fn a_proxy_url_with_a_password_in_it_is_a_secret_in_a_config_file() {
        let out = datacenter(&json!({ "http_proxy": "http://user:pass@proxy:3128" }));
        assert!(out.iter().any(|f| f.id == "cluster.proxy-credentials"));
    }
}
