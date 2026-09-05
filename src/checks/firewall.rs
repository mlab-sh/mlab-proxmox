//! Firewall and segmentation checks.
//!
//! Proxmox filters at four levels and every one of them has its own switch.
//! Most of what goes wrong is not a bad rule: it is a rule that applies to
//! nothing because a switch above or below it is off.

use serde_json::Value;

use std::collections::BTreeSet;

use crate::checks::{flag, i, prop, propstring, s, Finding, Severity};
use crate::collect::{Firewall, Guest, Node};

/// Cluster-level: the master switch and the default policies.
pub fn cluster(fw: &Firewall, guests: usize) -> Vec<Finding> {
    let mut out = Vec::new();
    let o = &fw.options;

    // `enable` defaults to 0: a cluster that never touched the firewall has
    // no packet filter at all, and the options object is nearly empty.
    let enabled = flag(o, "enable", false);
    if !enabled {
        out.push(
            Finding::new(
                "firewall.cluster-disabled",
                if guests > 0 { Severity::High } else { Severity::Medium },
                "cluster",
                "the cluster firewall is off",
                )
            .detail(format!(
                "`enable` is unset at the datacenter level, so no rule anywhere takes effect — \
                 including the {} rule(s) and any per-guest rule already written.",
                fw.rules.len()
            ))
            .remedy("Datacenter → Firewall → Options → Firewall: Yes. Create the `management` IPSet first, or you will lock yourself out of 8006."),
        );
    }

    for (key, dir) in [("policy_in", "inbound"), ("policy_forward", "forwarded")] {
        if s(o, key).eq_ignore_ascii_case("ACCEPT") {
            out.push(
                Finding::new(
                    "firewall.policy-accept",
                    Severity::High,
                    "cluster",
                    format!("the default {dir} policy is ACCEPT"),
                )
                .detail(format!(
                    "`{key}` is ACCEPT, so everything not matched by a rule is allowed. \
                     The Proxmox default is DROP."
                )),
            );
        }
    }

    if enabled && !fw.ipsets.iter().any(|x| s(x, "name") == "management") {
        out.push(
            Finding::new(
                "firewall.no-management-ipset",
                Severity::Low,
                "cluster",
                "no `management` IPSet",
            )
            .detail(
                "The firewall is on and nothing restricts who may reach the web interface, \
                 SSH and SPICE; the built-in management rules then allow them from anywhere.",
            ),
        );
    }

    if enabled && !flag(o, "ebtables", true) {
        out.push(
            Finding::new(
                "firewall.ebtables-off",
                Severity::Low,
                "cluster",
                "ebtables rules are disabled cluster-wide",
            )
            .detail("Nothing filters at the MAC layer, which is where the guest anti-spoofing rules live."),
        );
    }

    // Without rate limiting, a single loop fills the disk instead of the log.
    let ratelimit = propstring(&s(o, "log_ratelimit"), "enable");
    if !s(o, "log_ratelimit").is_empty() && prop(&ratelimit, "enable") == Some("0") {
        out.push(
            Finding::new(
                "firewall.log-ratelimit-off",
                Severity::Low,
                "cluster",
                "firewall log rate limiting is disabled",
            )
            .detail("A packet loop writes as fast as the disk accepts it."),
        );
    }

    out.extend(rules("cluster", &fw.rules));
    out.extend(security_groups(fw));
    out.extend(ipsets(fw));
    out.extend(unused_objects(fw));
    out
}

/// The rules that live inside a security group.
///
/// A rule of type `group` is a reference. Reading the referenced rules is the
/// difference between auditing a firewall and auditing a table of contents.
fn security_groups(fw: &Firewall) -> Vec<Finding> {
    let mut out = Vec::new();

    // Which groups the rules actually invoke.
    let invoked: BTreeSet<String> = fw
        .rules
        .iter()
        .filter(|r| s(r, "type") == "group")
        .map(|r| s(r, "action"))
        .collect();

    for g in &fw.groups {
        let name = s(g, "group");
        let group_rules = fw.group_rules.get(&name).cloned().unwrap_or_default();

        if group_rules.is_empty() {
            out.push(
                Finding::new(
                    "firewall.empty-group",
                    if invoked.contains(&name) {
                        Severity::Medium
                    } else {
                        Severity::Info
                    },
                    format!("group/{name}"),
                    format!("the security group {name} contains no rule"),
                )
                .detail(if invoked.contains(&name) {
                    "A rule invokes this group, and the group does nothing."
                } else {
                    "Defined and invoked by nothing."
                }),
            );
            continue;
        }

        // The same hygiene as anywhere else, now that the rules are visible.
        out.extend(rules(&format!("group/{name}"), &group_rules));
    }
    out
}

/// What the IP sets actually contain, rather than whether they exist.
fn ipsets(fw: &Firewall) -> Vec<Finding> {
    let mut out = Vec::new();
    for (name, members) in &fw.ipset_members {
        let open: Vec<String> = members
            .iter()
            .map(|m| s(m, "cidr"))
            .filter(|c| c == "0.0.0.0/0" || c == "::/0")
            .collect();
        if open.is_empty() {
            continue;
        }
        // `management` is the set the built-in rules use to decide who may
        // reach 8006, 22 and 3128, so a default route in it is the whole game.
        let severity = if name == "management" {
            Severity::High
        } else {
            Severity::Medium
        };
        out.push(
            Finding::new(
                "firewall.ipset-open",
                severity,
                format!("ipset/{name}"),
                format!("the IP set {name} contains {}", open.join(" and ")),
            )
            .detail(if name == "management" {
                "The management rules allow the web interface, SSH and SPICE from every member \
                 of this set. A default route in it restricts nothing at all."
            } else {
                "Every rule matching this set matches every source."
            }),
        );
    }
    out
}

/// Aliases and IP sets that no rule mentions.
fn unused_objects(fw: &Firewall) -> Vec<Finding> {
    if fw.refs.is_empty() && fw.aliases.is_empty() && fw.ipsets.is_empty() {
        return Vec::new();
    }
    // `refs` is what the rules can reach; anything defined outside it is dead
    // weight that still reads as configuration in a review.
    let referenced: BTreeSet<String> = fw.refs.iter().map(|r| s(r, "name")).collect();
    let mut unused: Vec<String> = Vec::new();
    for a in &fw.aliases {
        let n = s(a, "name");
        if !referenced.contains(&n) {
            unused.push(format!("alias {n}"));
        }
    }
    for i in &fw.ipsets {
        let n = s(i, "name");
        if !referenced.contains(&n) && n != "management" {
            unused.push(format!("ipset {n}"));
        }
    }
    if unused.is_empty() {
        return Vec::new();
    }
    vec![Finding::new(
        "firewall.unused-object",
        Severity::Info,
        "cluster",
        format!(
            "{} firewall object(s) are defined and referenced nowhere",
            unused.len()
        ),
    )
    .detail(unused.join(", "))]
}

/// Host-level: the per-node switch, and the rules that quietly do nothing.
pub fn node(n: &Node, cluster_enabled: bool) -> Vec<Finding> {
    let mut out = Vec::new();
    let subject = format!("node/{}", n.name);

    // Unlike the cluster switch, this one defaults to on.
    if !flag(&n.firewall, "enable", true) {
        out.push(
            Finding::new(
                "firewall.node-disabled",
                Severity::High,
                &subject,
                "host firewall rules are disabled on this node",
            )
            .detail("`enable: 0` in the node's firewall options overrides the datacenter setting."),
        );
    }

    // Forward rules are accepted into the configuration by both engines and
    // enforced by only one of them.
    let nftables = flag(&n.firewall, "nftables", false);
    let forwards = n
        .firewall_rules
        .iter()
        .filter(|r| s(r, "type") == "forward")
        .count();
    if forwards > 0 && !nftables {
        out.push(
            Finding::new(
                "firewall.forward-rules-ignored",
                Severity::High,
                &subject,
                format!("{forwards} forward rule(s) are never applied"),
            )
            .detail(
                "Rules in the forward direction only take effect under the nftables engine. \
                 The stock pve-firewall accepts them into the config and ignores them.",
            )
            .remedy("Either install proxmox-firewall and set `nftables: 1` on the node, or stop relying on these rules."),
        );
    }

    let on = cluster_enabled && flag(&n.firewall, "enable", true);

    // Connection tracking helpers parse application protocols in the kernel and
    // open pinholes from what they read. FTP and SIP helpers are the classic
    // way a firewall is talked into opening a port it never configured.
    let helpers = s(&n.firewall, "nf_conntrack_helpers");
    if on && !helpers.is_empty() {
        out.push(
            Finding::new(
                "firewall.conntrack-helpers",
                Severity::Medium,
                &subject,
                format!("connection tracking helpers are enabled: {helpers}"),
            )
            .detail(
                "A helper opens ports from what it parses in the traffic itself, so a guest that \
                 controls the payload controls the pinhole.",
            ),
        );
    }

    if on && flag(&n.firewall, "nf_conntrack_allow_invalid", false) {
        out.push(
            Finding::new(
                "firewall.conntrack-invalid",
                Severity::Medium,
                &subject,
                "packets that fail connection tracking are allowed",
            )
            .detail(
                "`nf_conntrack_allow_invalid: 1` lets through what the kernel could not place in \
                 any known connection — the shape of an evasion attempt.",
            ),
        );
    }

    // A firewall that logs nothing cannot answer what it dropped, which is the
    // only question worth asking after an incident.
    if on {
        let quiet: Vec<&str> = ["log_level_in", "log_level_out", "log_level_forward"]
            .into_iter()
            .filter(|k| {
                let v = s(&n.firewall, k);
                v.is_empty() || v == "nolog"
            })
            .collect();
        if quiet.len() == 3 {
            out.push(
                Finding::new(
                    "firewall.no-logging",
                    Severity::Medium,
                    &subject,
                    "the host firewall records nothing",
                )
                .detail(
                    "Every direction is at `nolog`, so `mlab-proxmox firewall log` and any \
                     later investigation have nothing to read.",
                )
                .remedy(
                    "Node → Firewall → Options → set the inbound log level to at least `info`.",
                ),
            );
        }
    }

    if cluster_enabled && !flag(&n.firewall, "tcpflags", false) {
        out.push(
            Finding::new(
                "firewall.tcpflags-off",
                Severity::Low,
                &subject,
                "illegal TCP flag combinations are not filtered",
            )
            .detail("`tcpflags` is off, which is the default."),
        );
    }

    out.extend(rules(&subject, &n.firewall_rules));
    out
}

/// Guest-level: the switch, the per-NIC switch, and the anti-spoofing options.
pub fn guest(g: &Guest, cluster_enabled: bool) -> Vec<Finding> {
    let mut out = Vec::new();
    let subject = g.subject();

    // Both default to off, and they have to agree: the guest switch arms the
    // rules, the NIC flag decides whether any packet reaches them.
    let guest_on = flag(&g.firewall, "enable", false);
    let nics: Vec<(String, Vec<(String, String)>)> = g
        .nets()
        .into_iter()
        .map(|(k, v)| (k, propstring(&v, "model")))
        .collect();
    let filtered: Vec<&String> = nics
        .iter()
        .filter(|(_, p)| prop(p, "firewall") == Some("1"))
        .map(|(k, _)| k)
        .collect();

    if !guest_on && !filtered.is_empty() {
        out.push(
            Finding::new(
                "firewall.guest-switch-off",
                Severity::High,
                &subject,
                format!(
                    "{} has the firewall flag on {} but the guest firewall is off",
                    g.label(),
                    filtered
                        .iter()
                        .map(|k| k.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )
            .detail(
                "The NIC is marked as filtered and the guest's own switch is off, so the rules \
                 written for it are inert.",
            ),
        );
    } else if guest_on && filtered.is_empty() && !nics.is_empty() {
        out.push(
            Finding::new(
                "firewall.nic-unfiltered",
                Severity::High,
                &subject,
                format!("{} has the firewall on but no filtered NIC", g.label()),
            )
            .detail(format!(
                "The guest firewall is enabled and {} rule(s) exist, but no `netN` carries \
                 `firewall=1`, so no packet is ever inspected.",
                g.firewall_rules.len()
            ))
            .remedy("Tick Firewall on the network device, or turn the guest firewall off and stop believing in it."),
        );
    } else if !guest_on && cluster_enabled && !nics.is_empty() && !g.template {
        out.push(
            Finding::new(
                "firewall.guest-unprotected",
                Severity::Medium,
                &subject,
                format!("{} has no firewall of its own", g.label()),
            )
            .detail(
                "Only the host and datacenter rules apply to this guest; nothing filters what \
                 it sends or receives on its own bridge.",
            ),
        );
    }

    if guest_on {
        if !flag(&g.firewall, "macfilter", true) {
            out.push(
                Finding::new(
                    "firewall.macfilter-off",
                    Severity::Medium,
                    &subject,
                    format!("{} may spoof its MAC address", g.label()),
                )
                .detail(
                    "`macfilter: 0` removes the check that the source MAC is the configured one.",
                ),
            );
        }
        // Without it, macfilter only pins the MAC: the guest still sends from
        // any address it likes.
        if !flag(&g.firewall, "ipfilter", false) {
            out.push(
                Finding::new(
                    "firewall.ipfilter-off",
                    Severity::Medium,
                    &subject,
                    format!("{} may send from any IP address", g.label()),
                )
                .detail(
                    "`ipfilter` is off, so nothing ties the guest's traffic to the addresses it \
                     was given. MAC filtering alone does not stop it.",
                ),
            );
        }

        if s(&g.firewall, "policy_in").eq_ignore_ascii_case("ACCEPT") {
            out.push(
                Finding::new(
                    "firewall.guest-policy-accept",
                    Severity::Medium,
                    &subject,
                    format!("{} accepts everything inbound by default", g.label()),
                )
                .detail("`policy_in: ACCEPT` on the guest firewall."),
            );
        }
        if flag(&g.firewall, "radv", false) {
            out.push(
                Finding::new(
                    "firewall.radv-allowed",
                    Severity::Medium,
                    &subject,
                    format!("{} may advertise itself as an IPv6 router", g.label()),
                )
                .detail(
                    "`radv: 1` lets the guest send Router Advertisements to its whole segment.",
                ),
            );
        }
    }

    for (name, members) in &g.firewall_ipsets {
        let open: Vec<String> = members
            .iter()
            .map(|m| s(m, "cidr"))
            .filter(|c| c == "0.0.0.0/0" || c == "::/0")
            .collect();
        if !open.is_empty() {
            out.push(
                Finding::new(
                    "firewall.ipset-open",
                    Severity::Medium,
                    &subject,
                    format!(
                        "the IP set {name} on {} contains {}",
                        g.label(),
                        open.join(" and ")
                    ),
                )
                .detail("Every rule matching this set matches every source."),
            );
        }
    }

    out.extend(rules(&subject, &g.firewall_rules));
    out
}

/// Rule hygiene, at whichever level the rules came from.
///
/// Ordering is deliberately not analysed: a verdict on shadowing needs the
/// full match semantics of both engines, and a wrong one is worse than none.
fn rules(subject: &str, rules: &[Value]) -> Vec<Finding> {
    let mut out = Vec::new();
    if rules.is_empty() {
        return out;
    }

    let disabled = rules.iter().filter(|r| !flag(r, "enable", true)).count();
    if disabled > 0 {
        out.push(
            Finding::new(
                "firewall.rules-disabled",
                Severity::Info,
                subject,
                format!("{disabled} of {} rule(s) are disabled", rules.len()),
            )
            .detail("Disabled rules stay in the configuration and read as protection in a review."),
        );
    }

    let unlogged: Vec<String> = rules
        .iter()
        .filter(|r| flag(r, "enable", true))
        .filter(|r| {
            let log = s(r, "log");
            log.is_empty() || log == "nolog"
        })
        .filter(|r| s(r, "action").eq_ignore_ascii_case("ACCEPT"))
        .map(describe)
        .collect();
    if !unlogged.is_empty() {
        out.push(
            Finding::new(
                "firewall.accept-unlogged",
                Severity::Low,
                subject,
                format!("{} ACCEPT rule(s) log nothing", unlogged.len()),
            )
            .detail(unlogged.join("; ")),
        );
    }

    // Two rules matching the same traffic: the second never decides anything,
    // and whoever edits the first will believe they changed the behaviour.
    let mut seen: std::collections::BTreeMap<String, i64> = std::collections::BTreeMap::new();
    let mut duplicates: Vec<String> = Vec::new();
    for r in rules.iter().filter(|r| flag(r, "enable", true)) {
        let key = [
            "type",
            "action",
            "macro",
            "proto",
            "dport",
            "sport",
            "source",
            "dest",
            "iface",
            "icmp-type",
        ]
        .iter()
        .map(|k| s(r, k))
        .collect::<Vec<_>>()
        .join("|");
        let pos = i(r, "pos").unwrap_or(-1);
        match seen.get(&key) {
            Some(first) => duplicates.push(format!("#{pos} repeats #{first}")),
            None => {
                seen.insert(key, pos);
            }
        }
    }
    if !duplicates.is_empty() {
        out.push(
            Finding::new(
                "firewall.duplicate-rule",
                Severity::Low,
                subject,
                format!("{} rule(s) are exact duplicates", duplicates.len()),
            )
            .detail(format!(
                "{}. Ordering is not analysed here, so this reports identical rules only, never \
                 which rule shadows which.",
                duplicates.join(", ")
            )),
        );
    }

    let wide: Vec<String> = rules
        .iter()
        .filter(|r| flag(r, "enable", true))
        .filter(|r| s(r, "action").eq_ignore_ascii_case("ACCEPT"))
        .filter(|r| {
            let src = s(r, "source");
            (src.is_empty() || src == "0.0.0.0/0" || src == "::/0") && !s(r, "dport").is_empty()
        })
        .map(describe)
        .collect();
    if !wide.is_empty() {
        out.push(
            Finding::new(
                "firewall.accept-from-anywhere",
                Severity::Medium,
                subject,
                format!("{} rule(s) accept a port from any source", wide.len()),
            )
            .detail(wide.join("; ")),
        );
    }

    out
}

/// A rule in one line, the way the GUI writes it.
fn describe(r: &Value) -> String {
    let pos = i(r, "pos").unwrap_or(-1);
    let mut parts = vec![format!("#{pos} {}", s(r, "action"))];
    for (label, key) in [
        ("", "macro"),
        ("", "proto"),
        ("dport", "dport"),
        ("sport", "sport"),
    ] {
        let v = s(r, key);
        if v.is_empty() {
            continue;
        }
        parts.push(if label.is_empty() {
            v
        } else {
            format!("{label} {v}")
        });
    }
    let src = s(r, "source");
    parts.push(format!(
        "from {}",
        if src.is_empty() { "any" } else { &src }
    ));
    // A rule with a destination or bound to one interface is far narrower than
    // the same line without them, and printing it without says the opposite.
    let dest = s(r, "dest");
    if !dest.is_empty() {
        parts.push(format!("to {dest}"));
    }
    let iface = s(r, "iface");
    if !iface.is_empty() {
        parts.push(format!("on {iface}"));
    }
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn node_fixture(firewall: Value) -> Node {
        Node {
            name: "n1".into(),
            status: Value::Null,
            version: Value::Null,
            subscription: Value::Null,
            services: vec![],
            network: vec![],
            dns: Value::Null,
            time: Value::Null,
            certificates: vec![],
            repositories: Value::Null,
            disks: vec![],
            pci: vec![],
            thin_pools: vec![],
            zfs_pools: vec![],
            hosts: Value::Null,
            firewall,
            firewall_rules: vec![],
            updates: None,
            packages: vec![],
        }
    }

    fn guest_with(config: Value, firewall: Value) -> Guest {
        Guest {
            node: "n1".into(),
            vmid: 100,
            kind: "qemu".into(),
            name: "test".into(),
            status: "running".into(),
            template: false,
            config,
            firewall,
            firewall_rules: vec![],
            firewall_ipsets: Default::default(),
            pending: vec![],
            agent: Default::default(),
            snapshots: vec![],
        }
    }

    #[test]
    fn an_empty_options_object_means_the_cluster_firewall_is_off() {
        let fw = Firewall {
            options: json!({ "digest": "abc" }),
            ..Default::default()
        };
        let out = cluster(&fw, 5);
        assert!(out
            .iter()
            .any(|f| f.id == "firewall.cluster-disabled" && f.severity == Severity::High));
    }

    #[test]
    fn rules_armed_on_a_nic_nobody_filters_are_reported() {
        let g = guest_with(
            json!({ "net0": "virtio=BC:24:11:00:00:01,bridge=vmbr0" }),
            json!({ "enable": 1 }),
        );
        let out = guest(&g, true);
        assert!(out.iter().any(|f| f.id == "firewall.nic-unfiltered"));
    }

    #[test]
    fn a_filtered_nic_on_a_guest_with_the_switch_off_is_the_other_half_of_the_trap() {
        let g = guest_with(
            json!({ "net0": "virtio=BC:24:11:00:00:01,bridge=vmbr0,firewall=1" }),
            json!({ "digest": "x" }),
        );
        let out = guest(&g, true);
        assert!(out.iter().any(|f| f.id == "firewall.guest-switch-off"));
    }

    #[test]
    fn forward_rules_without_nftables_are_flagged_once() {
        let n = node_fixture(json!({ "enable": 1, "nftables": 0 }));
        let mut n = n;
        n.firewall_rules = vec![json!({ "type": "forward", "action": "ACCEPT", "enable": 1 })];
        let out = node(&n, true);
        assert!(out.iter().any(|f| f.id == "firewall.forward-rules-ignored"));
    }

    #[test]
    fn a_security_group_is_audited_like_any_other_rule_list() {
        let mut fw = Firewall {
            options: json!({ "enable": 1 }),
            groups: vec![json!({ "group": "web" })],
            ..Default::default()
        };
        fw.group_rules.insert(
            "web".into(),
            vec![json!({
                "pos": 0, "action": "ACCEPT", "enable": 1,
                "proto": "tcp", "dport": "22", "source": ""
            })],
        );
        let out = cluster(&fw, 1);
        // The ACCEPT inside the group is found, and attributed to the group.
        let f = out
            .iter()
            .find(|f| f.id == "firewall.accept-from-anywhere")
            .unwrap();
        assert_eq!(f.subject, "group/web");
    }

    #[test]
    fn an_empty_group_matters_more_when_a_rule_invokes_it() {
        let mut fw = Firewall {
            options: json!({ "enable": 1 }),
            groups: vec![json!({ "group": "web" })],
            ..Default::default()
        };
        fw.group_rules.insert("web".into(), vec![]);
        let unused = cluster(&fw, 1);
        assert_eq!(
            unused
                .iter()
                .find(|f| f.id == "firewall.empty-group")
                .unwrap()
                .severity,
            Severity::Info
        );

        fw.rules = vec![json!({ "type": "group", "action": "web", "enable": 1 })];
        let invoked = cluster(&fw, 1);
        assert_eq!(
            invoked
                .iter()
                .find(|f| f.id == "firewall.empty-group")
                .unwrap()
                .severity,
            Severity::Medium
        );
    }

    #[test]
    fn a_default_route_in_the_management_set_restricts_nothing() {
        let mut fw = Firewall {
            options: json!({ "enable": 1 }),
            ipsets: vec![json!({ "name": "management" })],
            ..Default::default()
        };
        fw.ipset_members
            .insert("management".into(), vec![json!({ "cidr": "0.0.0.0/0" })]);
        let out = cluster(&fw, 1);
        let f = out.iter().find(|f| f.id == "firewall.ipset-open").unwrap();
        assert_eq!(f.severity, Severity::High);

        fw.ipset_members
            .insert("management".into(), vec![json!({ "cidr": "10.0.0.0/8" })]);
        assert!(!cluster(&fw, 1)
            .iter()
            .any(|f| f.id == "firewall.ipset-open"));
    }

    #[test]
    fn identical_rules_are_reported_and_ordering_is_not() {
        let rows = vec![
            json!({ "pos": 0, "action": "ACCEPT", "enable": 1, "proto": "tcp", "dport": "443", "source": "10.0.0.0/8" }),
            json!({ "pos": 1, "action": "ACCEPT", "enable": 1, "proto": "tcp", "dport": "443", "source": "10.0.0.0/8" }),
        ];
        let out = rules("cluster", &rows);
        let f = out
            .iter()
            .find(|f| f.id == "firewall.duplicate-rule")
            .unwrap();
        assert!(f.detail.contains("#1 repeats #0"));
        assert!(f.detail.contains("Ordering is not analysed"));
    }

    #[test]
    fn a_narrower_rule_is_not_a_duplicate_of_a_broader_one() {
        let rows = vec![
            json!({ "pos": 0, "action": "ACCEPT", "enable": 1, "proto": "tcp", "dport": "443" }),
            json!({ "pos": 1, "action": "ACCEPT", "enable": 1, "proto": "tcp", "dport": "443", "iface": "net0" }),
        ];
        assert!(!rules("cluster", &rows)
            .iter()
            .any(|f| f.id == "firewall.duplicate-rule"));
    }

    #[test]
    fn conntrack_helpers_and_invalid_packets_are_each_their_own_finding() {
        let n = node_fixture(json!({
            "enable": 1, "nf_conntrack_helpers": "ftp,sip",
            "nf_conntrack_allow_invalid": 1, "log_level_in": "info"
        }));
        let out = node(&n, true);
        assert!(out.iter().any(|f| f.id == "firewall.conntrack-helpers"));
        assert!(out.iter().any(|f| f.id == "firewall.conntrack-invalid"));
    }

    #[test]
    fn a_firewall_that_logs_nothing_is_reported_only_once_it_is_on() {
        let quiet = json!({ "enable": 1 });
        assert!(node(&node_fixture(quiet.clone()), true)
            .iter()
            .any(|f| f.id == "firewall.no-logging"));
        // Cluster switch off: the node's logging is not the problem to raise.
        assert!(!node(&node_fixture(quiet), false)
            .iter()
            .any(|f| f.id == "firewall.no-logging"));
        assert!(!node(
            &node_fixture(json!({ "enable": 1, "log_level_in": "info" })),
            true
        )
        .iter()
        .any(|f| f.id == "firewall.no-logging"));
    }

    #[test]
    fn a_guest_without_ip_filtering_can_still_spoof() {
        let g = guest_with(
            json!({ "net0": "virtio=AA,bridge=vmbr0,firewall=1" }),
            json!({ "enable": 1 }),
        );
        let out = guest(&g, true);
        assert!(out.iter().any(|f| f.id == "firewall.ipfilter-off"));

        let g = guest_with(
            json!({ "net0": "virtio=AA,bridge=vmbr0,firewall=1" }),
            json!({ "enable": 1, "ipfilter": 1 }),
        );
        assert!(!guest(&g, true)
            .iter()
            .any(|f| f.id == "firewall.ipfilter-off"));
    }

    #[test]
    fn objects_nothing_references_are_listed_once() {
        let fw = Firewall {
            options: json!({ "enable": 1 }),
            aliases: vec![json!({ "name": "old-office", "cidr": "10.1.0.0/16" })],
            refs: vec![json!({ "name": "in-use", "type": "alias" })],
            ..Default::default()
        };
        let out = cluster(&fw, 1);
        let f = out
            .iter()
            .find(|f| f.id == "firewall.unused-object")
            .unwrap();
        assert!(f.detail.contains("alias old-office"));
    }
}
