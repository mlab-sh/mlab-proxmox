//! Backup coverage, job health, retention, and the storage underneath.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::checks::{flag, i, s, Finding, Severity};
use crate::collect::Guest;

/// A backup task older than this, with nothing newer, means the schedule is
/// not running whatever the job says.
const STALE_BACKUP_DAYS: i64 = 14;

/// A guest whose newest backup is older than this is not protected, whatever
/// the job list says.
const STALE_FILE_DAYS: i64 = 14;

/// Fill levels at which a storage stops being able to accept a backup, and at
/// which a thin pool starts corrupting what it holds.
const FULL_PCT: f64 = 90.0;
const THIN_CRITICAL_PCT: f64 = 95.0;

pub fn all(
    jobs: &[Value],
    not_backed_up: &[Value],
    storages: &[Value],
    guests: &[Guest],
    tasks: &[Value],
    now: i64,
) -> Vec<Finding> {
    let mut out = Vec::new();
    out.extend(coverage(jobs, not_backed_up, guests));
    out.extend(job_health(jobs, storages, now));
    out.extend(outcomes(jobs, tasks, now));
    out.extend(storage_posture(storages));
    out
}

/// The checks that need more than the job list: the files that exist, the
/// space left, and the pools underneath.
pub fn continuity(
    jobs: &[Value],
    backups: &[Value],
    storage_status: &[Value],
    nodes: &[crate::collect::Node],
    guests: &[Guest],
    replication: &[Value],
    now: i64,
) -> Vec<Finding> {
    let mut out = Vec::new();
    out.extend(files(jobs, backups, guests, now));
    out.extend(capacity(storage_status));
    out.extend(pools(nodes));
    out.extend(replication_health(replication));
    out
}

/// What is actually on the storage, per guest.
///
/// A job covers a guest on paper. This is the only check that knows whether
/// the covering produced a file.
fn files(jobs: &[Value], backups: &[Value], guests: &[Guest], now: i64) -> Vec<Finding> {
    let mut out = Vec::new();
    if jobs.is_empty() {
        // `backup.no-jobs` already said it; repeating it per guest is noise.
        return out;
    }

    // Newest backup per guest.
    let mut newest: BTreeMap<i64, i64> = BTreeMap::new();
    for b in backups {
        let Some(vmid) = i(b, "vmid") else { continue };
        let ctime = i(b, "ctime").unwrap_or(0);
        newest
            .entry(vmid)
            .and_modify(|t| *t = (*t).max(ctime))
            .or_insert(ctime);
    }

    let mut never: Vec<String> = Vec::new();
    let mut stale: Vec<String> = Vec::new();
    for g in guests.iter().filter(|g| !g.template) {
        match newest.get(&g.vmid) {
            None => never.push(g.label()),
            Some(t) => {
                let age = (now - t) / 86_400;
                if age > STALE_FILE_DAYS {
                    stale.push(format!("{} ({age}d)", g.label()));
                }
            }
        }
    }

    if !never.is_empty() {
        out.push(
            Finding::new(
                "backup.no-file",
                Severity::High,
                "cluster",
                format!("{} guest(s) have no backup file at all", never.len()),
            )
            .detail(format!(
                "{}. A job covers them on paper and nothing has landed on any readable storage.",
                never.join(", ")
            )),
        );
    }
    if !stale.is_empty() {
        out.push(
            Finding::new(
                "backup.stale-file",
                Severity::High,
                "cluster",
                format!(
                    "{} guest(s) have no backup newer than {STALE_FILE_DAYS} days",
                    stale.len()
                ),
            )
            .detail(stale.join(", ")),
        );
    }

    // PBS records a verification verdict per snapshot; an unverified backup is
    // a file, not yet a restore.
    let failed: Vec<String> = backups
        .iter()
        .filter(|b| {
            b.get("verification")
                .and_then(|v| v.get("state"))
                .and_then(Value::as_str)
                == Some("failed")
        })
        .map(|b| s(b, "volid"))
        .collect();
    if !failed.is_empty() {
        out.push(
            Finding::new(
                "backup.verification-failed",
                Severity::High,
                "cluster",
                format!("{} backup(s) failed verification", failed.len()),
            )
            .detail(failed.join(", ")),
        );
    }

    // Snapshots are not backups, and a guest that has only snapshots usually
    // believes otherwise.
    let only_snapshots: Vec<String> = guests
        .iter()
        .filter(|g| !g.template)
        .filter(|g| !newest.contains_key(&g.vmid))
        .filter(|g| g.snapshots.iter().any(|x| s(x, "name") != "current"))
        .map(|g| g.label())
        .collect();
    if !only_snapshots.is_empty() {
        out.push(
            Finding::new(
                "backup.snapshots-only",
                Severity::Medium,
                "cluster",
                format!("{} guest(s) have snapshots and no backup", only_snapshots.len()),
            )
            .detail(format!(
                "{}. A snapshot lives on the same storage as the disk it protects and dies with it.",
                only_snapshots.join(", ")
            )),
        );
    }
    out
}

/// Space left, per storage, as the node reports it.
fn capacity(storage_status: &[Value]) -> Vec<Finding> {
    let mut out = Vec::new();
    for st in storage_status {
        let (Some(total), Some(used)) = (i(st, "total"), i(st, "used")) else {
            continue;
        };
        if total <= 0 {
            continue;
        }
        let pct = used as f64 * 100.0 / total as f64;
        if pct < FULL_PCT {
            continue;
        }
        let id = s(st, "storage");
        let holds_backups = s(st, "content").split(',').any(|c| c.trim() == "backup");
        out.push(
            Finding::new(
                "storage.almost-full",
                if holds_backups {
                    Severity::High
                } else {
                    Severity::Medium
                },
                format!("storage/{id}"),
                format!("{id} is {pct:.0}% full on {}", s(st, "node")),
            )
            .detail(if holds_backups {
                "It accepts backups, so the next one fails rather than rotating."
            } else {
                "Guests on it stop writing when it fills."
            }),
        );
    }
    out
}

/// Thin pools and ZFS pools, which fail differently from a full filesystem.
fn pools(nodes: &[crate::collect::Node]) -> Vec<Finding> {
    let mut out = Vec::new();
    for n in nodes {
        for pool in &n.thin_pools {
            let name = format!("{}/{}", s(pool, "vg"), s(pool, "lv"));
            for (label, used_key, size_key) in [
                ("data", "used", "lv_size"),
                ("metadata", "metadata_used", "metadata_size"),
            ] {
                let (Some(used), Some(size)) = (i(pool, used_key), i(pool, size_key)) else {
                    continue;
                };
                if size <= 0 {
                    continue;
                }
                let pct = used as f64 * 100.0 / size as f64;
                if pct < THIN_CRITICAL_PCT {
                    continue;
                }
                out.push(
                    Finding::new(
                        "storage.thin-pool-full",
                        Severity::Critical,
                        format!("node/{}", n.name),
                        format!("thin pool {name} is {pct:.0}% full ({label})"),
                    )
                    .detail(
                        "A thin pool that fills does not return an error to the guest, it \
                         corrupts what is already written. Metadata fills before data does.",
                    ),
                );
            }
        }

        for pool in &n.zfs_pools {
            let health = s(pool, "health");
            if health.is_empty() || health == "ONLINE" {
                continue;
            }
            out.push(
                Finding::new(
                    "storage.zfs-degraded",
                    Severity::High,
                    format!("node/{}", n.name),
                    format!("ZFS pool {} is {health}", s(pool, "name")),
                )
                .detail("Redundancy is reduced or gone; the next failure is the one that counts."),
            );
        }
    }
    out
}

/// Replication as it actually runs, rather than as it is configured.
fn replication_health(replication: &[Value]) -> Vec<Finding> {
    let mut out = Vec::new();
    for j in replication {
        let id = s(j, "id");
        let fails = i(j, "fail_count").unwrap_or(0);
        let error = s(j, "error");
        if fails == 0 && error.is_empty() {
            continue;
        }
        out.push(
            Finding::new(
                "backup.replication-failing",
                Severity::High,
                format!("replication/{id}"),
                format!("replication job {id} has failed {fails} time(s)"),
            )
            .detail(if error.is_empty() {
                format!("Guest {} towards {}.", s(j, "guest"), s(j, "target"))
            } else {
                error
            }),
        );
    }
    out
}

/// Which guests no job covers. The API computes the hard part for us.
fn coverage(jobs: &[Value], not_backed_up: &[Value], guests: &[Guest]) -> Vec<Finding> {
    let mut out = Vec::new();
    let real_guests = guests.iter().filter(|g| !g.template).count();

    if jobs.is_empty() && real_guests > 0 {
        out.push(
            Finding::new(
                "backup.no-jobs",
                Severity::High,
                "cluster",
                format!("no backup job exists, for {real_guests} guest(s)"),
            )
            .detail("Nothing is scheduled: every guest on this cluster is one mistake from gone.")
            .remedy("Datacenter → Backup → Add."),
        );
        return out;
    }

    if !not_backed_up.is_empty() {
        let names: Vec<String> = not_backed_up
            .iter()
            .map(|g| {
                let name = s(g, "name");
                let vmid = i(g, "vmid").unwrap_or(0);
                let kind = s(g, "type");
                let prefix = if kind == "lxc" { "ct" } else { "vm" };
                if name.is_empty() {
                    format!("{prefix}/{vmid}")
                } else {
                    format!("{name} ({prefix}/{vmid})")
                }
            })
            .collect();
        out.push(
            Finding::new(
                "backup.uncovered-guests",
                Severity::High,
                "cluster",
                format!("{} guest(s) are in no backup job", names.len()),
            )
            .detail(names.join(", "))
            .remedy(
                "Add them to a job, or set the job to `all` so new guests are covered by default.",
            ),
        );
    }
    out
}

fn job_health(jobs: &[Value], storages: &[Value], now: i64) -> Vec<Finding> {
    let mut out = Vec::new();

    // Local storages, by id: a job writing to one keeps the backup on the
    // machine it is meant to protect.
    let local: BTreeSet<String> = storages
        .iter()
        .filter(|st| !flag(st, "shared", false))
        .filter(|st| {
            matches!(
                s(st, "type").as_str(),
                "dir" | "lvm" | "lvmthin" | "zfspool" | "btrfs"
            )
        })
        .map(|st| s(st, "storage"))
        .collect();

    for j in jobs {
        let id = s(j, "id");
        let subject = format!("backup/{id}");
        let label = if s(j, "comment").is_empty() {
            id.clone()
        } else {
            format!("{} ({id})", s(j, "comment"))
        };

        if !flag(j, "enabled", true) {
            out.push(
                Finding::new(
                    "backup.job-disabled",
                    Severity::Medium,
                    &subject,
                    format!("backup job {label} is disabled"),
                )
                .detail("It stays in the list and covers nothing."),
            );
        }

        let store = s(j, "storage");
        if local.contains(&store) {
            out.push(
                Finding::new(
                    "backup.local-target",
                    Severity::Medium,
                    &subject,
                    format!("backup job {label} writes to local storage {store}"),
                )
                .detail(
                    "A backup on the node it protects survives a deleted guest and nothing else: \
                     not a failed disk, not a ransomed host.",
                ),
            );
        }

        let prune = s(j, "prune-backups");
        if !prune.is_empty() {
            let p = crate::checks::propstring(&prune, "");
            // `keep-all=1` means keep everything and would otherwise sum to
            // one, reading exactly like a policy that keeps a single copy.
            let keep_all = crate::checks::prop(&p, "keep-all") == Some("1");
            let total: i64 = p
                .iter()
                .filter(|(k, _)| k.starts_with("keep-") && k != "keep-all")
                .filter_map(|(_, v)| v.parse::<i64>().ok())
                .sum();
            if !keep_all && total == 1 {
                out.push(
                    Finding::new(
                        "backup.thin-retention",
                        Severity::Medium,
                        &subject,
                        format!("backup job {label} keeps a single copy"),
                    )
                    .detail(format!(
                        "`prune-backups: {prune}` — corruption that survives one cycle overwrites \
                         the only good copy."
                    )),
                );
            }
        }

        // `next-run` is the scheduler's own answer. In the past means the
        // schedule parses and never fires again.
        match i(j, "next-run") {
            None if flag(j, "enabled", true) => out.push(
                Finding::new(
                    "backup.schedule-never-fires",
                    Severity::High,
                    &subject,
                    format!("backup job {label} has no next run"),
                )
                .detail(format!(
                    "The scheduler cannot place `{}` on the calendar, so this job is configured \
                     and dormant.",
                    s(j, "schedule")
                )),
            ),
            Some(t) if t < now => out.push(
                Finding::new(
                    "backup.next-run-past",
                    Severity::High,
                    &subject,
                    format!("backup job {label} was due on {}", crate::pve::iso8601(t)),
                )
                .detail("Its next run is in the past, so the timer is not firing."),
            ),
            _ => {}
        }

        if s(j, "mailto").is_empty() && s(j, "notification-mode") == "legacy-sendmail" {
            out.push(
                Finding::new(
                    "backup.no-notification",
                    Severity::Low,
                    &subject,
                    format!("backup job {label} tells nobody when it fails"),
                )
                .detail("No `mailto`, and the job is on the legacy mail path."),
            );
        }
    }
    out
}

/// What the task log says actually happened, which is the only evidence a
/// schedule is more than an intention.
fn outcomes(jobs: &[Value], tasks: &[Value], now: i64) -> Vec<Finding> {
    let mut out = Vec::new();
    if jobs.is_empty() {
        return out;
    }

    let backups: Vec<&Value> = tasks.iter().filter(|t| s(t, "type") == "vzdump").collect();

    let failed: Vec<String> = backups
        .iter()
        .filter(|t| {
            let st = s(t, "status");
            !st.is_empty() && st != "OK"
        })
        .map(|t| {
            format!(
                "{} on {}: {}",
                s(t, "id"),
                s(t, "node"),
                s(t, "status").chars().take(60).collect::<String>()
            )
        })
        .collect();
    if !failed.is_empty() {
        out.push(
            Finding::new(
                "backup.recent-failure",
                Severity::High,
                "cluster",
                format!("{} backup task(s) failed recently", failed.len()),
            )
            .detail(failed.join("; ")),
        );
    }

    match backups.iter().filter_map(|t| i(t, "starttime")).max() {
        None => out.push(
            Finding::new(
                "backup.never-ran",
                Severity::High,
                "cluster",
                "no backup task appears in the recent task log",
            )
            .detail(
                "Jobs are configured but nothing in the visible history shows one running. The \
                 task log is finite, so this is evidence, not proof.",
            ),
        ),
        Some(last) if (now - last) / 86_400 > STALE_BACKUP_DAYS => out.push(
            Finding::new(
                "backup.stale",
                Severity::High,
                "cluster",
                format!(
                    "the last backup task ran {} days ago",
                    (now - last) / 86_400
                ),
            )
            .detail(format!("Last seen at {}.", crate::pve::iso8601(last))),
        ),
        _ => {}
    }
    out
}

/// The storages themselves: what they hold and who can reach them.
fn storage_posture(storages: &[Value]) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut backup_capable = 0;

    for st in storages {
        let id = s(st, "storage");
        let subject = format!("storage/{id}");
        let kind = s(st, "type");
        let content = s(st, "content");
        if content.split(',').any(|c| c.trim() == "backup") {
            backup_capable += 1;
        }

        if flag(st, "disable", false) {
            out.push(
                Finding::new(
                    "storage.disabled",
                    Severity::Info,
                    &subject,
                    format!("storage {id} is disabled"),
                )
                .detail("Still configured, still referenced by anything that used it."),
            );
        }

        if kind == "pbs" && s(st, "encryption-key").is_empty() {
            out.push(
                Finding::new(
                    "storage.pbs-unencrypted",
                    Severity::Medium,
                    &subject,
                    format!("backups sent to {id} are not encrypted at rest"),
                )
                .detail(
                    "No `encryption-key` on the storage, so the backup server — and anyone who \
                     reaches its datastore — reads guest disks in the clear.",
                ),
            );
        }

        // A PBS datastore reached without a fingerprint trusts whatever answers.
        if kind == "pbs" && s(st, "fingerprint").is_empty() {
            out.push(
                Finding::new(
                    "storage.pbs-unpinned",
                    Severity::Medium,
                    &subject,
                    format!("the backup server {id} is used without a pinned fingerprint"),
                )
                .detail(
                    "PBS serves its own certificate; without `fingerprint` the client accepts \
                     whichever host answers on that address.",
                ),
            );
        }

        if matches!(kind.as_str(), "nfs" | "cifs") {
            out.push(
                Finding::new(
                    "storage.network-filesystem",
                    Severity::Info,
                    &subject,
                    format!("{id} is a {kind} share"),
                )
                .detail(
                    "Guest disks and backups cross the network in whatever the export allows; \
                     the access control is the server's, not Proxmox's.",
                ),
            );
        }
    }

    if backup_capable == 0 && !storages.is_empty() {
        out.push(
            Finding::new(
                "storage.no-backup-target",
                Severity::High,
                "cluster",
                "no storage accepts backups",
            )
            .detail("Not one configured storage lists `backup` in its content types."),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn no_job_at_all_is_reported_once_and_stops_there() {
        let g = vec![Guest {
            node: "n".into(),
            vmid: 100,
            kind: "qemu".into(),
            name: "a".into(),
            status: "running".into(),
            template: false,
            config: Value::Null,
            firewall: Value::Null,
            firewall_rules: vec![],
            firewall_ipsets: Default::default(),
            pending: vec![],
            agent: Default::default(),
            snapshots: vec![],
        }];
        let out = coverage(&[], &[], &g);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "backup.no-jobs");
    }

    #[test]
    fn uncovered_guests_are_named_in_the_detail() {
        let jobs = vec![json!({ "id": "j1", "storage": "pbs" })];
        let nbu = vec![json!({ "vmid": 150, "name": "web01", "type": "qemu" })];
        let out = coverage(&jobs, &nbu, &[]);
        assert_eq!(out[0].id, "backup.uncovered-guests");
        assert!(out[0].detail.contains("web01 (vm/150)"));
    }

    #[test]
    fn a_job_writing_to_a_local_storage_is_not_offsite() {
        let jobs = vec![json!({ "id": "j1", "storage": "local", "enabled": 1, "next-run": 100 })];
        let storages = vec![json!({ "storage": "local", "type": "dir", "content": "backup" })];
        let out = job_health(&jobs, &storages, 0);
        assert!(out.iter().any(|f| f.id == "backup.local-target"));
    }

    #[test]
    fn a_shared_target_is_left_alone() {
        let jobs = vec![json!({ "id": "j1", "storage": "pbs", "enabled": 1, "next-run": 100 })];
        let storages = vec![
            json!({ "storage": "pbs", "type": "pbs", "shared": 1, "content": "backup", "fingerprint": "aa" }),
        ];
        assert!(job_health(&jobs, &storages, 0).is_empty());
    }

    #[test]
    fn a_failed_vzdump_task_outranks_the_schedule() {
        let jobs = vec![json!({ "id": "j1", "storage": "pbs" })];
        let tasks = vec![json!({
            "type": "vzdump", "status": "job errors", "id": "150",
            "node": "n1", "starttime": 1_000
        })];
        let out = outcomes(&jobs, &tasks, 1_100);
        assert!(out.iter().any(|f| f.id == "backup.recent-failure"));
    }

    fn guest_named(vmid: i64, name: &str) -> Guest {
        Guest {
            node: "n1".into(),
            vmid,
            kind: "qemu".into(),
            name: name.into(),
            status: "running".into(),
            template: false,
            config: Value::Null,
            firewall: Value::Null,
            firewall_rules: vec![],
            firewall_ipsets: Default::default(),
            pending: vec![],
            agent: Default::default(),
            snapshots: vec![],
        }
    }

    #[test]
    fn a_job_that_produced_no_file_is_not_a_backup() {
        let jobs = vec![json!({ "id": "j1", "storage": "pbs", "enabled": 1, "next-run": 100 })];
        let guests = vec![guest_named(150, "web01")];
        let out = files(&jobs, &[], &guests, 1_000_000);
        let f = out.iter().find(|f| f.id == "backup.no-file").unwrap();
        assert!(f.detail.contains("web01"));
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn a_backup_older_than_a_fortnight_is_reported_with_its_age() {
        let jobs = vec![json!({ "id": "j1", "storage": "pbs", "enabled": 1, "next-run": 100 })];
        let guests = vec![guest_named(150, "web01")];
        let now = 30 * 86_400;
        let backups = vec![json!({ "vmid": 150, "ctime": 0, "volid": "pbs:backup/vm-150" })];
        let out = files(&jobs, &backups, &guests, now);
        assert!(out.iter().any(|f| f.id == "backup.stale-file"));

        let fresh = vec![json!({ "vmid": 150, "ctime": now - 3600, "volid": "x" })];
        assert!(!files(&jobs, &fresh, &guests, now)
            .iter()
            .any(|f| f.id.starts_with("backup.stale")));
    }

    #[test]
    fn snapshots_without_a_backup_are_called_what_they_are() {
        let jobs = vec![json!({ "id": "j1", "storage": "pbs", "enabled": 1, "next-run": 100 })];
        let mut g = guest_named(150, "web01");
        g.snapshots = vec![json!({ "name": "pre-upgrade" })];
        let out = files(&jobs, &[], &[g], 1_000);
        assert!(out.iter().any(|f| f.id == "backup.snapshots-only"));
    }

    #[test]
    fn a_backup_storage_that_is_nearly_full_outranks_an_image_one() {
        let full_backup = json!({ "storage": "pbs", "node": "n1", "total": 100, "used": 95, "content": "backup" });
        let full_images = json!({ "storage": "lvm", "node": "n1", "total": 100, "used": 95, "content": "images" });
        assert_eq!(capacity(&[full_backup])[0].severity, Severity::High);
        assert_eq!(capacity(&[full_images])[0].severity, Severity::Medium);
        let roomy = json!({ "storage": "pbs", "node": "n1", "total": 100, "used": 40, "content": "backup" });
        assert!(capacity(&[roomy]).is_empty());
    }

    #[test]
    fn thin_metadata_fills_before_the_data_and_both_are_critical() {
        let mut n = node_fixture();
        n.thin_pools = vec![json!({
            "vg": "pve", "lv": "data",
            "lv_size": 1000, "used": 100,
            "metadata_size": 100, "metadata_used": 99
        })];
        let out = pools(std::slice::from_ref(&n));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::Critical);
        assert!(out[0].title.contains("metadata"));
    }

    #[test]
    fn a_degraded_zfs_pool_is_reported_and_an_online_one_is_not() {
        let mut n = node_fixture();
        n.zfs_pools = vec![
            json!({ "name": "tank", "health": "DEGRADED" }),
            json!({ "name": "rpool", "health": "ONLINE" }),
        ];
        let out = pools(std::slice::from_ref(&n));
        assert_eq!(out.len(), 1);
        assert!(out[0].title.contains("tank"));
    }

    #[test]
    fn a_replication_job_with_failures_is_not_replication() {
        let jobs = vec![json!({
            "id": "100-0", "guest": 100, "target": "n2",
            "fail_count": 3, "error": "connection refused"
        })];
        let out = replication_health(&jobs);
        assert_eq!(out[0].severity, Severity::High);
        assert!(out[0].detail.contains("connection refused"));
    }

    #[test]
    fn a_schedule_the_scheduler_cannot_place_is_a_dormant_job() {
        let jobs =
            vec![json!({ "id": "j1", "storage": "pbs", "enabled": 1, "schedule": "nonsense" })];
        let out = job_health(&jobs, &[], 1_000);
        assert!(out.iter().any(|f| f.id == "backup.schedule-never-fires"));

        let past = vec![json!({ "id": "j1", "storage": "pbs", "enabled": 1, "next-run": 10 })];
        assert!(job_health(&past, &[], 1_000)
            .iter()
            .any(|f| f.id == "backup.next-run-past"));
    }

    fn node_fixture() -> crate::collect::Node {
        crate::collect::Node {
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
            firewall: Value::Null,
            firewall_rules: vec![],
            updates: None,
            packages: vec![],
        }
    }
}
