//! Detection over what the cluster already wrote down.
//!
//! There is no event stream in the Proxmox API, so this is not real time. It
//! is the cluster log and the task log, read once, and turned into the two
//! questions worth asking of them: who failed to get in, and who got a shell.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::checks::{i, s, Finding, Severity};

/// Failed authentications above this count, from one source, stop being a
/// typo and start being an attempt.
const BRUTE_FORCE: usize = 5;

pub fn all(cluster_log: &[Value], tasks: &[Value], now: i64) -> Vec<Finding> {
    let mut out = Vec::new();
    out.extend(authentication(cluster_log));
    out.extend(host_consoles(tasks, now));
    out.extend(failed_tasks(tasks));
    out
}

/// Authentication, as `pvedaemon` records it in the cluster log.
///
/// The log is finite and rotates, so a count here bounds what happened rather
/// than measuring it — which is exactly how the finding is worded.
fn authentication(log: &[Value]) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut failures: BTreeMap<String, usize> = BTreeMap::new();
    let mut succeeded: usize = 0;

    for row in log {
        let msg = s(row, "msg");
        let lower = msg.to_lowercase();
        if lower.contains("authentication failure") || lower.contains("auth failed") {
            // The user is in the message rather than the field when the login
            // never resolved to an account.
            let who = extract(&msg, "user=")
                .or_else(|| extract(&msg, "user '"))
                .unwrap_or_else(|| s(row, "user"));
            let from = extract(&msg, "rhost=").unwrap_or_default();
            let key = match (who.is_empty(), from.is_empty()) {
                (false, false) => format!("{who} from {from}"),
                (false, true) => who,
                (true, false) => format!("(unknown) from {from}"),
                (true, true) => "(unknown)".to_string(),
            };
            *failures.entry(key).or_default() += 1;
        } else if lower.contains("successful auth") {
            succeeded += 1;
        }
    }

    if failures.is_empty() {
        return out;
    }
    let total: usize = failures.values().sum();
    let worst = failures.values().copied().max().unwrap_or(0);
    let detail = failures
        .iter()
        .map(|(who, n)| format!("{who}: {n}"))
        .collect::<Vec<_>>()
        .join(", ");

    out.push(
        Finding::new(
            "detection.auth-failures",
            if worst >= BRUTE_FORCE {
                Severity::High
            } else {
                Severity::Medium
            },
            "cluster",
            format!("{total} failed authentication(s) in the visible log"),
        )
        .detail(format!(
            "{detail}. {succeeded} succeeded over the same window. The cluster log rotates, so \
             this bounds what happened rather than measuring it."
        )),
    );
    out
}

/// A shell on the hypervisor itself, which no guest-level control touches.
fn host_consoles(tasks: &[Value], now: i64) -> Vec<Finding> {
    let recent: Vec<&Value> = tasks
        .iter()
        .filter(|t| s(t, "type") == "vncshell" || s(t, "type") == "spiceshell")
        .filter(|t| {
            i(t, "starttime")
                .map(|x| now - x < 7 * 86_400)
                .unwrap_or(false)
        })
        .collect();
    if recent.is_empty() {
        return Vec::new();
    }

    let mut by_user: BTreeMap<String, usize> = BTreeMap::new();
    for t in &recent {
        *by_user.entry(s(t, "user")).or_default() += 1;
    }
    vec![Finding::new(
        "detection.host-console",
        Severity::Info,
        "cluster",
        format!(
            "{} root shell(s) opened on a node in the last 7 days",
            recent.len()
        ),
    )
    .detail(format!(
        "{}. A host console is a root shell outside every guest-level control, and it is the \
         one action worth recognising in this log.",
        by_user
            .iter()
            .map(|(u, n)| format!("{u}: {n}"))
            .collect::<Vec<_>>()
            .join(", ")
    ))]
}

/// Anything that ended badly, excluding what the backup checks already own.
fn failed_tasks(tasks: &[Value]) -> Vec<Finding> {
    let failed: Vec<&Value> = tasks
        .iter()
        .filter(|t| s(t, "type") != "vzdump")
        .filter(|t| {
            let st = s(t, "status");
            !st.is_empty() && st != "OK"
        })
        .collect();
    if failed.is_empty() {
        return Vec::new();
    }
    let detail = failed
        .iter()
        .take(10)
        .map(|t| {
            format!(
                "{} {} by {}: {}",
                s(t, "type"),
                s(t, "id"),
                s(t, "user"),
                s(t, "status").chars().take(50).collect::<String>()
            )
        })
        .collect::<Vec<_>>()
        .join("; ");

    vec![Finding::new(
        "detection.failed-tasks",
        Severity::Low,
        "cluster",
        format!("{} task(s) ended in an error", failed.len()),
    )
    .detail(detail)]
}

/// The value following `key` in a log line, up to the next space.
fn extract(msg: &str, key: &str) -> Option<String> {
    let start = msg.find(key)? + key.len();
    let rest = &msg[start..];
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '\'' || c == ',')
        .unwrap_or(rest.len());
    let v = rest[..end].trim();
    (!v.is_empty()).then(|| v.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_failed_login_is_attributed_to_a_user_and_a_source() {
        let log = vec![json!({
            "tag": "pvedaemon", "pri": "3", "user": "root@pam",
            "msg": "authentication failure; rhost=203.0.113.7 user=root@pam msg=Authentication failure"
        })];
        let out = authentication(&log);
        assert_eq!(out.len(), 1);
        assert!(out[0].detail.contains("root@pam from 203.0.113.7"));
        assert_eq!(out[0].severity, Severity::Medium);
    }

    #[test]
    fn repetition_from_one_source_turns_a_typo_into_an_attempt() {
        let row = json!({
            "tag": "pvedaemon", "pri": "3", "user": "",
            "msg": "authentication failure; rhost=203.0.113.7 user=admin@pve"
        });
        let log = vec![
            row.clone(),
            row.clone(),
            row.clone(),
            row.clone(),
            row.clone(),
            row,
        ];
        assert_eq!(authentication(&log)[0].severity, Severity::High);
    }

    #[test]
    fn a_successful_login_alone_says_nothing() {
        let log = vec![json!({
            "tag": "pvedaemon", "pri": "6", "user": "root@pam",
            "msg": "successful auth for user 'root@pam'"
        })];
        assert!(authentication(&log).is_empty());
    }

    #[test]
    fn a_host_console_is_recognised_and_a_guest_console_is_not() {
        let tasks = vec![
            json!({ "type": "vncshell", "user": "root@pam", "starttime": 900_000 }),
            json!({ "type": "vncproxy", "user": "root@pam", "starttime": 900_000, "id": "150" }),
        ];
        let out = host_consoles(&tasks, 1_000_000);
        assert_eq!(out.len(), 1);
        assert!(out[0].title.contains("1 root shell"));
    }

    #[test]
    fn an_old_console_session_falls_out_of_the_window() {
        let tasks = vec![json!({ "type": "vncshell", "user": "root@pam", "starttime": 0 })];
        assert!(host_consoles(&tasks, 30 * 86_400).is_empty());
    }

    #[test]
    fn backup_failures_are_left_to_the_backup_checks() {
        let tasks = vec![
            json!({ "type": "vzdump", "status": "job errors", "id": "150", "user": "root@pam" }),
            json!({ "type": "qmstart", "status": "start failed", "id": "151", "user": "ops@pve" }),
        ];
        let out = failed_tasks(&tasks);
        assert_eq!(out.len(), 1);
        assert!(out[0].detail.contains("qmstart"));
        assert!(!out[0].detail.contains("vzdump"));
    }

    #[test]
    fn a_key_that_is_absent_extracts_to_nothing() {
        assert_eq!(extract("no rhost here", "rhost="), None);
        assert_eq!(
            extract("rhost=10.0.0.1 user=x", "rhost="),
            Some("10.0.0.1".into())
        );
    }
}
