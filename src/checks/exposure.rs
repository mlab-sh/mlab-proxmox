//! What this cluster looks like from outside, and what leaves it.

use serde_json::Value;

use crate::checks::{flag, i, s, Finding, Severity};
use crate::collect::Node;
use crate::pve::iso8601;

/// A certificate closer than this to its expiry is worth acting on.
const CERT_WARN_DAYS: i64 = 30;

/// Services whose absence changes what the host is.
const CRITICAL_SERVICES: [(&str, &str); 4] = [
    ("pve-firewall", "the packet filter is not running"),
    ("pveproxy", "the API and web interface are down"),
    ("pvestatd", "no node reports its state"),
    ("corosync", "cluster membership is not maintained"),
];

/// Any one of these keeps the clock right; the finding is that none does.
const TIME_SERVICES: [&str; 3] = ["chrony", "systemd-timesyncd", "ntpsec"];

pub fn all(nodes: &[Node], metrics: &[Value], notifications: &[Value], now: i64) -> Vec<Finding> {
    let mut out = Vec::new();
    for n in nodes {
        out.extend(certificates(n, now));
        out.extend(services(n));
        out.extend(clock(n, now));
        out.extend(disks(n));
        out.extend(addresses(n));
        out.extend(rootfs(n));
        out.extend(resolution(n));
    }
    out.extend(egress(metrics, notifications));
    out
}

fn certificates(n: &Node, now: i64) -> Vec<Finding> {
    let mut out = Vec::new();
    let subject = format!("node/{}", n.name);

    // pveproxy-ssl.pem is the certificate an operator installed; when there is
    // none, pveproxy falls back to pve-ssl.pem, the one the cluster CA issued.
    // Whichever of the two exists is what a browser and this CLI actually see.
    let has_custom = n
        .certificates
        .iter()
        .any(|c| s(c, "filename") == "pveproxy-ssl.pem");
    let served = if has_custom {
        "pveproxy-ssl.pem"
    } else {
        "pve-ssl.pem"
    };

    for c in &n.certificates {
        let file = s(c, "filename");
        let public = file == served;
        let issuer = s(c, "issuer");
        let subj = s(c, "subject");

        if let Some(notafter) = i(c, "notafter") {
            let days = (notafter - now) / 86_400;
            if days < 0 {
                out.push(
                    Finding::new(
                        "exposure.certificate-expired",
                        Severity::High,
                        &subject,
                        format!("{file} expired {} days ago", -days),
                    )
                    .detail(format!("Not after {}.", iso8601(notafter))),
                );
            } else if days < CERT_WARN_DAYS {
                out.push(
                    Finding::new(
                        "exposure.certificate-expiring",
                        Severity::Medium,
                        &subject,
                        format!("{file} expires in {days} days"),
                    )
                    .detail(format!("Not after {}.", iso8601(notafter))),
                );
            }
        }

        if public && (issuer == subj || issuer.contains("Proxmox Virtual Environment")) {
            out.push(
                Finding::new(
                    "exposure.certificate-self-signed",
                    Severity::Low,
                    &subject,
                    "the web interface serves a self-signed certificate",
                )
                .detail(format!(
                    "Issued by {issuer}. Every client has to be told to trust it, which trains \
                     everyone to click through certificate warnings.",
                ))
                .remedy("Datacenter → ACME for a Let's Encrypt certificate, or upload your own."),
            );
        }

        if public {
            let sans: Vec<String> = c
                .get("san")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            // A browser matches the name it dialled, so a certificate that
            // names neither the node nor a wildcard covering it warns on every
            // visit whatever else is right about it.
            let covered = sans.is_empty()
                || sans.iter().any(|x| {
                    x == &n.name
                        || x.starts_with(&format!("{}.", n.name))
                        || x.starts_with("*.")
                        || x.parse::<std::net::IpAddr>().is_ok()
                });
            if !covered {
                out.push(
                    Finding::new(
                        "exposure.certificate-san-mismatch",
                        Severity::Medium,
                        &subject,
                        format!("{file} does not name this node"),
                    )
                    .detail(format!("Subject alternative names: {}.", sans.join(", "))),
                );
            }
        }

        if let Some(bits) = i(c, "public-key-bits") {
            if s(c, "public-key-type") == "rsa" && bits < 2048 {
                out.push(Finding::new(
                    "exposure.certificate-weak-key",
                    Severity::High,
                    &subject,
                    format!("{file} has a {bits}-bit RSA key"),
                ));
            }
        }
    }
    out
}

fn services(n: &Node) -> Vec<Finding> {
    let mut out = Vec::new();
    let subject = format!("node/{}", n.name);
    let fw_on = flag(&n.firewall, "enable", true);

    for (name, why) in CRITICAL_SERVICES {
        let Some(svc) = n.services.iter().find(|s_| s(s_, "name") == name) else {
            continue;
        };
        let state = s(svc, "state");
        if state == "running" {
            continue;
        }
        // corosync is meant to be dead on a standalone node.
        if name == "corosync" && state == "dead" {
            continue;
        }
        // A stopped firewall daemon only matters if the firewall is meant to run.
        if name == "pve-firewall" && !fw_on {
            continue;
        }
        out.push(
            Finding::new(
                "exposure.service-not-running",
                Severity::High,
                &subject,
                format!("{name} is {state}"),
            )
            .detail(format!("{}.", capitalize(why))),
        );
    }

    // Certificates, tickets, corosync and every log correlation rest on the
    // clock, and no other check notices when nothing is keeping it.
    let known: Vec<&Value> = n
        .services
        .iter()
        .filter(|svc| TIME_SERVICES.contains(&s(svc, "name").as_str()))
        .collect();
    if !known.is_empty() && !known.iter().any(|svc| s(svc, "state") == "running") {
        out.push(
            Finding::new(
                "exposure.no-time-sync",
                Severity::Medium,
                &subject,
                "no time synchronisation service is running",
            )
            .detail(format!(
                "{} present and stopped.",
                known
                    .iter()
                    .map(|svc| s(svc, "name"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        );
    }

    out
}

/// The root filesystem, which is where the cluster configuration lives.
fn rootfs(n: &Node) -> Vec<Finding> {
    let Some(fs) = n.status.get("rootfs") else {
        return Vec::new();
    };
    let (Some(total), Some(used)) = (i(fs, "total"), i(fs, "used")) else {
        return Vec::new();
    };
    if total <= 0 {
        return Vec::new();
    }
    let pct = used as f64 * 100.0 / total as f64;
    if pct < 85.0 {
        return Vec::new();
    }
    vec![Finding::new(
        "exposure.rootfs-full",
        if pct >= 95.0 {
            Severity::Critical
        } else {
            Severity::High
        },
        format!("node/{}", n.name),
        format!("the root filesystem is {pct:.0}% full"),
    )
    .detail(
        "pmxcfs keeps the cluster configuration under /etc/pve, backed by this filesystem. A \
         full root stops configuration changes, task logs and, on a cluster, quorum work.",
    )]
}

/// Whether the node can resolve its own cluster name.
fn resolution(n: &Node) -> Vec<Finding> {
    let hosts = n
        .hosts
        .get("data")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if hosts.is_empty() {
        return Vec::new();
    }

    // The name has to map to a real address, not to the loopback: corosync and
    // migration both dial whatever this resolves to.
    let mut mapped_to: Option<String> = None;
    for line in hosts.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut parts = line.split_whitespace();
        let Some(addr) = parts.next() else { continue };
        if parts.any(|name| name == n.name) {
            mapped_to = Some(addr.to_string());
            break;
        }
    }

    match mapped_to {
        None => vec![Finding::new(
            "exposure.name-unresolved",
            Severity::Medium,
            format!("node/{}", n.name),
            format!("{} does not appear in its own /etc/hosts", n.name),
        )
        .detail(
            "Cluster membership and migration dial the node by name. Proxmox expects the name \
             to resolve locally rather than through DNS.",
        )],
        Some(addr) if addr.starts_with("127.") => vec![Finding::new(
            "exposure.name-loopback",
            Severity::High,
            format!("node/{}", n.name),
            format!("{} resolves to {addr} on itself", n.name),
        )
        .detail(
            "A node name pointing at the loopback breaks corosync and every migration towards \
             it: the other members are handed an address that means `themselves`.",
        )],
        Some(_) => Vec::new(),
    }
}

fn clock(n: &Node, now: i64) -> Vec<Finding> {
    let Some(t) = i(&n.time, "time") else {
        return Vec::new();
    };
    let drift = (t - now).abs();
    // Anything under a minute is this CLI's own round trip and the API's
    // one-second resolution, not a real problem.
    if drift > 60 {
        return vec![Finding::new(
            "exposure.clock-drift",
            Severity::Medium,
            format!("node/{}", n.name),
            format!("the node clock is {drift}s away from this machine's"),
        )
        .detail(
            "Certificate validation, ticket lifetimes, corosync and every log correlation \
             depend on the clock. Check that a time synchronisation service is running.",
        )];
    }
    Vec::new()
}

fn disks(n: &Node) -> Vec<Finding> {
    let mut out = Vec::new();
    let subject = format!("node/{}", n.name);
    for d in &n.disks {
        let health = s(d, "health");
        let dev = s(d, "devpath");
        if health.is_empty() || health == "PASSED" || health == "OK" {
            continue;
        }
        out.push(
            Finding::new(
                "exposure.disk-health",
                Severity::High,
                &subject,
                format!("{dev} reports SMART health {health}"),
            )
            .detail(format!(
                "{} {}, {} bytes.",
                s(d, "vendor"),
                s(d, "model"),
                i(d, "size").unwrap_or(0)
            )),
        );
    }
    out
}

/// Public addresses on a node interface: the difference between a lab behind
/// a router and a host on the open internet.
fn addresses(n: &Node) -> Vec<Finding> {
    let mut out = Vec::new();
    for iface in &n.network {
        let addr = s(iface, "address");
        if addr.is_empty() || is_private_v4(&addr) {
            continue;
        }
        out.push(
            Finding::new(
                "exposure.public-address",
                Severity::Medium,
                format!("node/{}", n.name),
                format!("{} carries the public address {addr}", s(iface, "iface")),
            )
            .detail(
                "The API on 8006, SPICE on 3128 and the VNC range are reachable from wherever \
                 that address is routed unless something in front of them says otherwise.",
            ),
        );
    }
    out
}

/// Where cluster data goes on its own.
fn egress(metrics: &[Value], notifications: &[Value]) -> Vec<Finding> {
    let mut out = Vec::new();

    for m in metrics {
        if flag(m, "disable", false) {
            continue;
        }
        out.push(
            Finding::new(
                "exposure.metrics-export",
                Severity::Info,
                format!("metrics/{}", s(m, "id")),
                format!(
                    "metrics are shipped to {}:{} over {}",
                    s(m, "server"),
                    i(m, "port").unwrap_or(0),
                    s(m, "type")
                ),
            )
            .detail("Guest names, sizes and load leave the cluster continuously on this path."),
        );
    }

    for t in notifications {
        if flag(t, "disable", false) {
            continue;
        }
        let kind = s(t, "type");
        if matches!(kind.as_str(), "webhook" | "gotify") {
            out.push(
                Finding::new(
                    "exposure.notification-target",
                    Severity::Info,
                    format!("notification/{}", s(t, "name")),
                    format!(
                        "{} notifications go to an external {kind} endpoint",
                        s(t, "name")
                    ),
                )
                .detail("Task output and failure text are sent there, including guest names."),
            );
        }
    }
    out
}

fn is_private_v4(addr: &str) -> bool {
    let o: Vec<u8> = addr
        .split('.')
        .filter_map(|p| p.parse::<u8>().ok())
        .collect();
    if o.len() != 4 {
        // Not IPv4: link-local and unique-local IPv6 are the private cases.
        let lower = addr.to_ascii_lowercase();
        return lower.starts_with("fe80")
            || lower.starts_with("fd")
            || lower.starts_with("fc")
            || lower == "::1";
    }
    match (o[0], o[1]) {
        (10, _) => true,
        (127, _) => true,
        (172, b) if (16..=31).contains(&b) => true,
        (192, 168) => true,
        (169, 254) => true,
        _ => false,
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn node_with(certificates: Vec<Value>, services: Vec<Value>, network: Vec<Value>) -> Node {
        Node {
            name: "n1".into(),
            status: Value::Null,
            version: Value::Null,
            subscription: Value::Null,
            services,
            network,
            dns: Value::Null,
            time: Value::Null,
            certificates,
            repositories: Value::Null,
            disks: vec![],
            pci: vec![],
            thin_pools: vec![],
            zfs_pools: vec![],
            hosts: Value::Null,
            firewall: json!({ "enable": 1 }),
            firewall_rules: vec![],
            updates: None,
            packages: vec![],
        }
    }

    #[test]
    fn private_ranges_are_not_exposure() {
        for a in [
            "10.0.0.1",
            "192.168.1.20",
            "172.16.4.4",
            "127.0.0.1",
            "fe80::1",
        ] {
            assert!(is_private_v4(a), "{a} should read as private");
        }
        for a in ["8.8.8.8", "51.15.1.2", "172.32.0.1"] {
            assert!(!is_private_v4(a), "{a} should read as public");
        }
    }

    #[test]
    fn an_expired_certificate_outranks_one_about_to_expire() {
        let n = node_with(
            vec![
                json!({ "filename": "pveproxy-ssl.pem", "notafter": 500, "issuer": "x", "subject": "y" }),
            ],
            vec![],
            vec![],
        );
        let out = certificates(&n, 1_000_000);
        assert!(out
            .iter()
            .any(|f| f.id == "exposure.certificate-expired" && f.severity == Severity::High));
    }

    #[test]
    fn a_self_signed_leaf_is_reported_once_for_the_public_certificate() {
        let n = node_with(
            vec![
                json!({ "filename": "pve-ssl.pem", "issuer": "PVE CA", "subject": "PVE CA", "notafter": 9_000_000_000i64 }),
                json!({ "filename": "pveproxy-ssl.pem", "issuer": "Proxmox Virtual Environment", "subject": "n1", "notafter": 9_000_000_000i64 }),
            ],
            vec![],
            vec![],
        );
        let out = certificates(&n, 0);
        assert_eq!(
            out.iter()
                .filter(|f| f.id == "exposure.certificate-self-signed")
                .count(),
            1
        );
    }

    #[test]
    fn a_stopped_firewall_only_matters_when_the_firewall_is_on() {
        let stopped = vec![json!({ "name": "pve-firewall", "state": "stopped" })];
        let mut n = node_with(vec![], stopped.clone(), vec![]);
        assert!(!services(&n).is_empty());
        n.firewall = json!({ "enable": 0 });
        assert!(services(&n).is_empty());
    }

    #[test]
    fn a_full_root_filesystem_is_the_cluster_configuration_running_out_of_room() {
        let mut n = node_with(vec![], vec![], vec![]);
        n.status = json!({ "rootfs": { "total": 100, "used": 96 } });
        let out = rootfs(&n);
        assert_eq!(out[0].severity, Severity::Critical);
        n.status = json!({ "rootfs": { "total": 100, "used": 88 } });
        assert_eq!(rootfs(&n)[0].severity, Severity::High);
        n.status = json!({ "rootfs": { "total": 100, "used": 40 } });
        assert!(rootfs(&n).is_empty());
    }

    #[test]
    fn a_node_name_on_the_loopback_breaks_every_other_node() {
        let mut n = node_with(vec![], vec![], vec![]);
        n.hosts = json!({ "data": "127.0.1.1 n1.lan n1\n10.0.0.5 other\n" });
        let out = resolution(&n);
        assert_eq!(out[0].severity, Severity::High);

        n.hosts = json!({ "data": "127.0.0.1 localhost\n10.0.0.5 n1.lan n1\n" });
        assert!(resolution(&n).is_empty());

        n.hosts = json!({ "data": "127.0.0.1 localhost\n" });
        assert_eq!(resolution(&n)[0].id, "exposure.name-unresolved");
    }

    #[test]
    fn a_clock_with_no_service_keeping_it_is_reported_once() {
        let n = node_with(
            vec![],
            vec![json!({ "name": "chrony", "state": "stopped" })],
            vec![],
        );
        assert!(services(&n).iter().any(|f| f.id == "exposure.no-time-sync"));

        let n = node_with(
            vec![],
            vec![json!({ "name": "chrony", "state": "running" })],
            vec![],
        );
        assert!(!services(&n).iter().any(|f| f.id == "exposure.no-time-sync"));
    }

    #[test]
    fn a_certificate_that_names_another_host_warns_on_every_visit() {
        let n = node_with(
            vec![json!({
                "filename": "pveproxy-ssl.pem", "issuer": "Let's Encrypt", "subject": "old.example",
                "notafter": 9_000_000_000i64, "san": ["old.example"]
            })],
            vec![],
            vec![],
        );
        assert!(certificates(&n, 0)
            .iter()
            .any(|f| f.id == "exposure.certificate-san-mismatch"));

        let n = node_with(
            vec![json!({
                "filename": "pveproxy-ssl.pem", "issuer": "Let's Encrypt", "subject": "n1.lan",
                "notafter": 9_000_000_000i64, "san": ["n1.lan", "n1"]
            })],
            vec![],
            vec![],
        );
        assert!(!certificates(&n, 0)
            .iter()
            .any(|f| f.id == "exposure.certificate-san-mismatch"));
    }
}
