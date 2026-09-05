//! The graded checks, as pure functions over collected data.
//!
//! Nothing in here performs I/O. A check takes what [`crate::collect`] already
//! fetched and returns [`Finding`]s, which makes every rule testable against a
//! literal and keeps the collection honest about what it could not read.

pub mod access;
pub mod backup;
pub mod cluster;
pub mod detection;
pub mod exposure;
pub mod firewall;
pub mod guests;
pub mod patch;

use std::fmt;

use colored::Colorize;
use serde::Serialize;
use serde_json::Value;

/// How much a finding matters. `Unreadable` is not a grade but an admission:
/// the check could not run because the token was refused the data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
    Unreadable,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
            Severity::Unreadable => "unreadable",
        }
    }

    pub fn paint(self) -> colored::ColoredString {
        match self {
            Severity::Critical => "critical".red().bold(),
            Severity::High => "high".red(),
            Severity::Medium => "medium".yellow(),
            Severity::Low => "low".normal(),
            Severity::Info => "info".cyan(),
            Severity::Unreadable => "unreadable".dimmed(),
        }
    }

    /// Findings at or above this level are what `audit --fail-on` acts on.
    pub fn from_name(s: &str) -> Option<Severity> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            "info" => Severity::Info,
            "none" | "never" => return None,
            _ => return None,
        })
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One graded observation about one subject.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Stable dotted identifier, so a finding can be suppressed or tracked.
    pub id: &'static str,
    pub severity: Severity,
    /// What the finding is about: `cluster`, `node/pve1`, `vm/150`.
    pub subject: String,
    pub title: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remedy: Option<String>,
}

impl Finding {
    pub fn new(
        id: &'static str,
        severity: Severity,
        subject: impl Into<String>,
        title: impl Into<String>,
    ) -> Self {
        Finding {
            id,
            severity,
            subject: subject.into(),
            title: title.into(),
            detail: String::new(),
            remedy: None,
        }
    }

    pub fn detail(mut self, d: impl Into<String>) -> Self {
        self.detail = d.into();
        self
    }

    pub fn remedy(mut self, r: impl Into<String>) -> Self {
        self.remedy = Some(r.into());
        self
    }
}

/// A run of checks: what they found, and what they could not look at.
#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn extend(&mut self, other: Vec<Finding>) {
        self.findings.extend(other);
    }

    /// Worst first, then by subject so a node's findings stay together.
    pub fn sorted(&self) -> Vec<&Finding> {
        let mut v: Vec<&Finding> = self.findings.iter().collect();
        v.sort_by(|a, b| {
            a.severity
                .cmp(&b.severity)
                .then_with(|| a.subject.cmp(&b.subject))
                .then_with(|| a.id.cmp(b.id))
        });
        v
    }

    pub fn count(&self, s: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == s).count()
    }

    /// The worst severity present, ignoring what could not be read.
    pub fn worst(&self) -> Option<Severity> {
        self.findings
            .iter()
            .map(|f| f.severity)
            .filter(|s| *s != Severity::Unreadable)
            .min()
    }
}

/// Every check, over one collected inventory.
///
/// The order is the order a reader wants: what the cluster is, then who can
/// reach it, then what protects it, then what would survive losing it.
pub fn run_all(inv: &crate::collect::Inventory, now: i64) -> Report {
    let mut r = Report::default();
    let fw_on = flag(&inv.firewall.options, "enable", false);

    r.extend(cluster::all(
        &inv.cluster_status,
        &inv.totem,
        &inv.options,
        &inv.ha_resources,
        &inv.replication,
        &inv.qdevice,
        &inv.ha_status,
    ));
    r.extend(access::all(&inv.access, now));
    r.extend(firewall::cluster(&inv.firewall, inv.guests.len()));
    for n in &inv.nodes {
        r.extend(firewall::node(n, fw_on));
    }
    for g in &inv.guests {
        r.extend(firewall::guest(g, fw_on));
        r.extend(guests::all(g, now));
    }
    r.extend(guests::iommu(&inv.guests, &inv.nodes));
    r.extend(patch::all(&inv.nodes));
    r.extend(exposure::all(
        &inv.nodes,
        &inv.metrics_servers,
        &inv.notification_targets,
        now,
    ));
    r.extend(backup::all(
        &inv.backup_jobs,
        &inv.not_backed_up,
        &inv.storages,
        &inv.guests,
        &inv.tasks,
        now,
    ));
    r.extend(backup::continuity(
        &inv.backup_jobs,
        &inv.backups,
        &inv.storage_status,
        &inv.nodes,
        &inv.guests,
        &inv.replication,
        now,
    ));
    r.extend(detection::all(&inv.cluster_log, &inv.tasks, now));
    r
}

// ---- helpers shared by the check modules -----------------------------------

/// Read a string field, empty when absent.
pub fn s(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// Read an integer field.
pub fn i(v: &Value, key: &str) -> Option<i64> {
    match v.get(key) {
        Some(Value::Number(n)) => n.as_i64(),
        // PVE hands back "1" as often as 1, depending on the endpoint.
        Some(Value::String(t)) => t.parse().ok(),
        Some(Value::Bool(b)) => Some(i64::from(*b)),
        _ => None,
    }
}

/// A flag that PVE writes as 0/1, with the default it takes when absent.
pub fn flag(v: &Value, key: &str, default: bool) -> bool {
    match i(v, key) {
        Some(n) => n != 0,
        None => default,
    }
}

/// Parse one of Proxmox's property strings: `virtio=AA:BB,bridge=vmbr0,tag=10`.
///
/// The first element may be bare, in which case it is stored under the key
/// given as `first`, and also under its own key when it looks like `k=v`.
pub fn propstring(raw: &str, first: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (idx, part) in raw.split(',').enumerate() {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part.split_once('=') {
            Some((k, v)) => out.push((k.trim().to_string(), v.trim().to_string())),
            None if idx == 0 && !first.is_empty() => {
                out.push((first.to_string(), part.to_string()))
            }
            None => out.push((part.to_string(), "1".to_string())),
        }
    }
    out
}

/// Look one key up in a parsed property string.
pub fn prop<'a>(parsed: &'a [(String, String)], key: &str) -> Option<&'a str> {
    parsed
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_property_string_keeps_its_bare_first_element() {
        let p = propstring(
            "virtio=BC:24:11:00:00:01,bridge=vmbr0,tag=10,firewall=1",
            "model",
        );
        assert_eq!(prop(&p, "bridge"), Some("vmbr0"));
        assert_eq!(prop(&p, "tag"), Some("10"));
        assert_eq!(prop(&p, "virtio"), Some("BC:24:11:00:00:01"));

        let p = propstring("local-lvm:vm-150-disk-0,size=32G", "volume");
        assert_eq!(prop(&p, "volume"), Some("local-lvm:vm-150-disk-0"));
        assert_eq!(prop(&p, "size"), Some("32G"));
    }

    #[test]
    fn a_bare_feature_reads_as_enabled() {
        let p = propstring("nesting=1,keyctl", "");
        assert_eq!(prop(&p, "nesting"), Some("1"));
        assert_eq!(prop(&p, "keyctl"), Some("1"));
    }

    #[test]
    fn flags_take_their_documented_default_when_absent() {
        let v = json!({ "enable": 0, "macfilter": "1" });
        assert!(!flag(&v, "enable", true));
        assert!(flag(&v, "macfilter", false));
        assert!(flag(&v, "ndp", true), "absent means the API default");
    }

    #[test]
    fn a_report_sorts_worst_first_and_ignores_unreadable_in_its_verdict() {
        let mut r = Report::default();
        r.extend(vec![
            Finding::new("b", Severity::Medium, "vm/2", "medium"),
            Finding::new("a", Severity::Critical, "vm/1", "critical"),
            Finding::new("c", Severity::Unreadable, "node/x", "dark"),
        ]);
        assert_eq!(r.sorted()[0].id, "a");
        assert_eq!(r.worst(), Some(Severity::Critical));
        assert_eq!(r.count(Severity::Unreadable), 1);
    }
}
