//! Access control checks: who holds what, and how long they keep it.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::checks::{flag, i, s, Finding, Severity};
use crate::collect::Access;
use crate::pve::iso8601;

/// Privileges that let their holder change the system or hand themselves more
/// of it. A role carrying one of these is an administrative role whatever it
/// is called.
const DANGEROUS: [&str; 6] = [
    "Permissions.Modify",
    "Realm.Allocate",
    "Sys.Modify",
    "Sys.PowerMgmt",
    "Sys.Console",
    "User.Modify",
];

pub fn all(a: &Access, now: i64) -> Vec<Finding> {
    let mut out = Vec::new();
    out.extend(privileged_grants(a));
    out.extend(custom_roles(a));
    out.extend(acl_hygiene(a));
    out.extend(users(a, now));
    out.extend(tokens(a, now));
    out.extend(realms(a));
    out.extend(realm_sync(a));
    out
}

/// The factors one account actually has, and whether it is locked out.
///
/// A registered factor is not the same as a usable one: an entry can be
/// disabled, and recovery keys are a way back in rather than a second factor
/// for daily use.
struct Factors {
    usable: Vec<String>,
    recovery_only: bool,
    registered: bool,
    locked: bool,
}

fn factors_of(a: &Access, userid: &str, now: i64) -> Factors {
    let row = a.tfa.iter().find(|t| s(t, "userid") == userid);
    let Some(row) = row else {
        return Factors {
            usable: Vec::new(),
            recovery_only: false,
            registered: false,
            locked: false,
        };
    };

    let entries: Vec<&Value> = row
        .get("entries")
        .and_then(Value::as_array)
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    let enabled: Vec<String> = entries
        .iter()
        .filter(|e| flag(e, "enable", true))
        .map(|e| s(e, "type"))
        .collect();
    let usable: Vec<String> = enabled
        .iter()
        .filter(|t| t.as_str() != "recovery")
        .cloned()
        .collect();

    let locked = flag(row, "totp-locked", false)
        || i(row, "tfa-locked-until").map(|u| u > now).unwrap_or(false);

    Factors {
        recovery_only: usable.is_empty() && !enabled.is_empty(),
        usable,
        registered: !entries.is_empty(),
        locked,
    }
}

/// ACL entries that hand out administrative power, and how far they reach.
fn privileged_grants(a: &Access) -> Vec<Finding> {
    let mut out = Vec::new();

    // Which roles are administrative, from this cluster's own role list rather
    // than from a hardcoded name: a custom role is just as powerful.
    let admin_roles: BTreeSet<String> = a
        .roles
        .iter()
        .filter(|r| {
            let privs = s(r, "privs");
            s(r, "roleid") == "Administrator"
                || DANGEROUS.iter().any(|d| privs.split(',').any(|p| p == *d))
        })
        .map(|r| s(r, "roleid"))
        .collect();

    for e in &a.acl {
        let role = s(e, "roleid");
        if !admin_roles.contains(&role) {
            continue;
        }
        let path = s(e, "path");
        let who = s(e, "ugid");
        let kind = s(e, "type");
        let propagate = flag(e, "propagate", true);
        // A grant to a group says nothing about who actually holds it, which
        // is the whole reason group grants are easy to lose track of.
        let members = if kind == "group" {
            group_members(a, &who)
        } else {
            Vec::new()
        };
        let severity = if path == "/" {
            Severity::High
        } else {
            Severity::Medium
        };
        out.push(
            Finding::new(
                "access.privileged-grant",
                severity,
                format!("{kind}/{who}"),
                format!("{who} holds {role} on {path}"),
            )
            .detail(format!(
                "{}{}{}",
                if role == "Administrator" {
                    "Administrator carries every privilege there is. ".to_string()
                } else {
                    format!("{role} carries at least one privilege that changes the system. ")
                },
                if propagate {
                    "The grant propagates to everything below that path."
                } else {
                    "The grant does not propagate."
                },
                match (kind.as_str(), members.is_empty()) {
                    ("group", false) => format!(" Members: {}.", members.join(", ")),
                    ("group", true) => " The group has no member today, so the grant waits for whoever is added next.".to_string(),
                    _ => String::new(),
                }
            )),
        );
    }
    out
}

/// Hand-made roles that quietly include a privilege nobody expected.
fn custom_roles(a: &Access) -> Vec<Finding> {
    let mut out = Vec::new();
    for r in &a.roles {
        // `special` marks the built-in roles, which are not this check's business.
        if flag(r, "special", false) {
            continue;
        }
        let id = s(r, "roleid");
        let privs = s(r, "privs");
        let found: Vec<&str> = DANGEROUS
            .iter()
            .copied()
            .filter(|d| privs.split(',').any(|p| p == *d))
            .collect();
        if found.is_empty() {
            continue;
        }
        out.push(
            Finding::new(
                "access.custom-role-privileged",
                Severity::Medium,
                format!("role/{id}"),
                format!("the custom role {id} is not read-only"),
            )
            .detail(format!("It carries {}.", found.join(", "))),
        );
    }
    out
}

/// The members of one group, from the index, which already carries them.
fn group_members(a: &Access, groupid: &str) -> Vec<String> {
    a.groups
        .iter()
        .find(|g| s(g, "groupid") == groupid)
        .map(|g| {
            s(g, "users")
                .split(',')
                .map(str::trim)
                .filter(|u| !u.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// The state of the access control list itself, rather than of what it grants.
fn acl_hygiene(a: &Access) -> Vec<Finding> {
    let mut out = Vec::new();

    let users: BTreeSet<String> = a.users.iter().map(|u| s(u, "userid")).collect();
    let groups: BTreeSet<String> = a.groups.iter().map(|g| s(g, "groupid")).collect();
    let tokens: BTreeSet<String> = a
        .tokens
        .iter()
        .map(|t| format!("{}!{}", s(t, "userid"), s(t, "tokenid")))
        .collect();
    let roles: BTreeSet<String> = a.roles.iter().map(|r| s(r, "roleid")).collect();

    for e in &a.acl {
        let who = s(e, "ugid");
        let kind = s(e, "type");
        let path = s(e, "path");
        let role = s(e, "roleid");

        // An entry naming something that no longer exists grants nothing today
        // and grants everything again the moment the name is reused.
        let known = match kind.as_str() {
            "user" => users.contains(&who),
            "group" => groups.contains(&who),
            // Token lists need User.Modify; without them, silence is the only
            // honest answer rather than a false orphan.
            "token" => !a.tokens_readable || tokens.contains(&who),
            _ => true,
        };
        if !known {
            out.push(
                Finding::new(
                    "access.acl-orphan",
                    Severity::Medium,
                    format!("{kind}/{who}"),
                    format!("{who} holds {role} on {path} and does not exist"),
                )
                .detail(
                    "The grant is inert until something is created with that exact name, at \
                     which point it applies again without anyone deciding so.",
                ),
            );
        }

        if !roles.contains(&role) {
            out.push(Finding::new(
                "access.acl-unknown-role",
                Severity::Medium,
                format!("{kind}/{who}"),
                format!("the role {role} referenced on {path} does not exist"),
            ));
        }

        if role == "NoAccess" {
            out.push(
                Finding::new(
                    "access.acl-noaccess",
                    Severity::Info,
                    format!("{kind}/{who}"),
                    format!("{who} is denied access on {path}"),
                )
                .detail(
                    "NoAccess is the only way to carve an exception out of an inherited grant. \
                     Listed so the exception is visible next to what it cuts into.",
                ),
            );
        }
    }

    // Proxmox resolves a deeper entry by *replacing* what was inherited, not by
    // adding to it, so a narrower role further down silently removes rights.
    for e in &a.acl {
        let who = s(e, "ugid");
        let kind = s(e, "type");
        let path = s(e, "path");
        let role = s(e, "roleid");
        if path == "/" {
            continue;
        }
        for parent in &a.acl {
            if s(parent, "ugid") != who || s(parent, "type") != kind {
                continue;
            }
            let ppath = s(parent, "path");
            let prole = s(parent, "roleid");
            let covers = ppath == "/" || path.starts_with(&format!("{ppath}/"));
            if !covers || ppath == path || !flag(parent, "propagate", true) || prole == role {
                continue;
            }
            out.push(
                Finding::new(
                    "access.acl-override",
                    Severity::Low,
                    format!("{kind}/{who}"),
                    format!("{role} on {path} replaces the inherited {prole} from {ppath}"),
                )
                .detail(
                    "Proxmox does not merge the two: a permission at a deeper level replaces \
                     what was inherited, so this path may grant less than the one above it.",
                ),
            );
        }
    }
    out
}

/// Directory synchronisation, which decides what a departure actually removes.
fn realm_sync(a: &Access) -> Vec<Finding> {
    let mut out = Vec::new();
    for j in &a.realm_sync {
        let id = s(j, "id");
        let realm = s(j, "realm");
        let subject = format!("realm-sync/{id}");

        if !flag(j, "enabled", true) {
            out.push(
                Finding::new(
                    "access.realm-sync-disabled",
                    Severity::Low,
                    &subject,
                    format!("the sync job for realm {realm} is disabled"),
                )
                .detail("The directory and this cluster drift apart from here on."),
            );
            continue;
        }

        // `remove-vanished` lists what a disappearance takes with it. Without
        // `acl`, a user deleted from the directory keeps their grants.
        let removes = s(j, "remove-vanished");
        if !removes.split(';').any(|p| p.trim() == "acl") {
            out.push(
                Finding::new(
                    "access.realm-sync-keeps-acl",
                    Severity::Medium,
                    &subject,
                    format!("a user removed from {realm} keeps their permissions here"),
                )
                .detail(format!(
                    "`remove-vanished` is {}, which does not include `acl`. The account may go \
                     and its grants stay, ready for the next account with that name.",
                    if removes.is_empty() {
                        "unset"
                    } else {
                        &removes
                    }
                )),
            );
        }

        if i(j, "last-run").is_none() {
            out.push(Finding::new(
                "access.realm-sync-never-ran",
                Severity::Low,
                &subject,
                format!("the sync job for realm {realm} has never run"),
            ));
        }
    }
    out
}

fn users(a: &Access, now: i64) -> Vec<Finding> {
    let mut out = Vec::new();

    // Realms may enforce a factor for everyone they authenticate, which makes
    // a per-account registration unnecessary.
    let realm_tfa: BTreeSet<String> = a
        .realms
        .iter()
        .filter(|r| !s(r, "tfa").is_empty())
        .map(|r| s(r, "realm"))
        .collect();

    for u in &a.users {
        let id = s(u, "userid");
        let subject = format!("user/{id}");
        let enabled = flag(u, "enable", true);
        let realm = id.split('@').nth(1).unwrap_or_default().to_string();

        if !enabled {
            out.push(
                Finding::new(
                    "access.user-disabled",
                    Severity::Info,
                    &subject,
                    format!("{id} is disabled but still configured"),
                )
                .detail(
                    "Its ACL entries survive the disable. Its tokens do not: Proxmox refuses \
                     them at authentication while the account is off.",
                ),
            );
            continue;
        }

        // root@pam is the account that always exists and always matters, so
        // every gap in its second factor outranks the same gap elsewhere.
        let severity = if id == "root@pam" {
            Severity::High
        } else {
            Severity::Medium
        };
        let f = factors_of(a, &id, now);
        let enforced = realm_tfa.contains(&realm);

        if !f.registered && !enforced {
            out.push(
                Finding::new(
                    "access.no-tfa",
                    severity,
                    &subject,
                    format!("{id} has no second factor"),
                )
                .detail(format!(
                    "No TFA entry is registered for this account and the {realm} realm does not \
                     enforce one, so a password is the only thing between it and the API."
                )),
            );
        } else if f.registered && f.usable.is_empty() && !f.recovery_only && !enforced {
            out.push(
                Finding::new(
                    "access.tfa-all-disabled",
                    severity,
                    &subject,
                    format!("{id} has a second factor, and every one of them is disabled"),
                )
                .detail(
                    "The entries are still listed, so the account reads as protected in the \
                     user list and authenticates on a password alone.",
                ),
            );
        } else if f.recovery_only && !enforced {
            out.push(
                Finding::new(
                    "access.tfa-recovery-only",
                    severity,
                    &subject,
                    format!("{id} has recovery keys and no real second factor"),
                )
                .detail(
                    "Recovery keys are a way back in after losing a device, not a factor for \
                     daily use: they are single-use, printed, and usually stored somewhere \
                     considerably less safe than a phone.",
                ),
            );
        }

        if f.locked {
            out.push(
                Finding::new(
                    "access.tfa-locked",
                    Severity::Medium,
                    &subject,
                    format!("{id} is currently locked out of its second factor"),
                )
                .detail(
                    "Proxmox locks an account after repeated second-factor failures. Either \
                     the owner is struggling with their device, or somebody has the password \
                     and is working on the rest.",
                ),
            );
        }

        if let Some(exp) = i(u, "expire") {
            if exp != 0 && exp < now {
                out.push(
                    Finding::new(
                        "access.user-expired",
                        Severity::Low,
                        &subject,
                        format!("{id} expired on {}", iso8601(exp)),
                    )
                    .detail("The account is still enabled; PVE refuses it at login."),
                );
            }
        }
    }

    // A group nobody belongs to still carries whatever was granted to it.
    for g in &a.groups {
        let id = s(g, "groupid");
        if !group_members(a, &id).is_empty() {
            continue;
        }
        let grants = a
            .acl
            .iter()
            .filter(|e| s(e, "type") == "group" && s(e, "ugid") == id)
            .count();
        if grants > 0 {
            out.push(
                Finding::new(
                    "access.empty-group-grant",
                    Severity::Low,
                    format!("group/{id}"),
                    format!("the group {id} holds {grants} grant(s) and has no member"),
                )
                .detail(
                    "Nothing uses it today, and whoever is added to it next inherits those \
                     grants without a decision being made about them.",
                ),
            );
        }
    }
    out
}

fn tokens(a: &Access, now: i64) -> Vec<Finding> {
    let mut out = Vec::new();

    if !a.tokens_readable {
        out.push(
            Finding::new(
                "access.tokens-unreadable",
                Severity::Unreadable,
                "cluster",
                "the API tokens of other users cannot be listed",
            )
            .detail(
                "Listing a user's tokens needs `User.Modify` on that user's group, which a \
                 read-only role does not carry. Nothing is claimed here about token hygiene.",
            )
            .remedy("Grant User.Modify if you want this audited, knowing it also grants user administration."),
        );
        return out;
    }

    for t in &a.tokens {
        let user = s(t, "userid");
        let name = s(t, "tokenid");
        let id = format!("{user}!{name}");
        let subject = format!("token/{id}");

        if !flag(t, "privsep", true) {
            out.push(
                Finding::new(
                    "access.token-full-privileges",
                    Severity::Medium,
                    &subject,
                    format!("{id} has privilege separation off"),
                )
                .detail(
                    "The token carries every privilege of its user, so revoking the token is the \
                     only way to narrow it.",
                ),
            );
        }

        match i(t, "expire") {
            Some(0) | None => out.push(
                Finding::new(
                    "access.token-no-expiry",
                    Severity::Low,
                    &subject,
                    format!("{id} never expires"),
                )
                .detail("Abandoned automation keeps working until somebody notices the token."),
            ),
            Some(e) if e < now => out.push(
                Finding::new(
                    "access.token-expired",
                    Severity::Info,
                    &subject,
                    format!("{id} expired on {}", iso8601(e)),
                )
                .detail("It is refused at authentication but still listed."),
            ),
            _ => {}
        }
    }
    out
}

fn realms(a: &Access) -> Vec<Finding> {
    let mut out = Vec::new();
    for r in &a.realms {
        let realm = s(r, "realm");
        let kind = s(r, "type");
        if matches!(kind.as_str(), "ldap" | "ad") && s(r, "tfa").is_empty() {
            out.push(
                Finding::new(
                    "access.realm-no-tfa",
                    Severity::Low,
                    format!("realm/{realm}"),
                    format!("the {kind} realm {realm} does not enforce a second factor"),
                )
                .detail("Every account it authenticates relies on the directory password alone."),
            );
        }
    }

    // True on every Proxmox host, and worth saying once rather than never.
    out.push(
        Finding::new(
            "access.realm-list-public",
            Severity::Info,
            "cluster",
            format!(
                "the realm list is readable without authentication ({} realm(s))",
                a.realms.len()
            ),
        )
        .detail(
            "`GET /access/domains` is world-readable so the login box can render, so anyone who \
             reaches port 8006 learns which directories authenticate this cluster.",
        ),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn access() -> Access {
        Access {
            users: vec![json!({ "userid": "root@pam", "enable": 1 })],
            roles: vec![
                json!({ "roleid": "Administrator", "privs": "", "special": 1 }),
                json!({ "roleid": "NoAccess", "privs": "", "special": 1 }),
                json!({ "roleid": "MlabAudit", "privs": "Sys.Audit,Sys.Syslog", "special": 0 }),
            ],
            realms: vec![json!({ "realm": "pam", "type": "pam" })],
            ..Default::default()
        }
    }

    fn tfa_row(userid: &str, entries: Value) -> Value {
        json!({ "userid": userid, "entries": entries })
    }

    #[test]
    fn an_administrator_grant_at_the_root_is_high() {
        let mut a = access();
        a.acl = vec![json!({
            "path": "/", "type": "user", "ugid": "ops@pve",
            "roleid": "Administrator", "propagate": 1
        })];
        let out = privileged_grants(&a);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::High);
    }

    #[test]
    fn a_group_grant_names_the_people_behind_it() {
        let mut a = access();
        a.groups = vec![json!({ "groupid": "ops", "users": "alice@pve,bob@pve" })];
        a.acl = vec![json!({
            "path": "/", "type": "group", "ugid": "ops",
            "roleid": "Administrator", "propagate": 1
        })];
        let out = privileged_grants(&a);
        assert!(out[0].detail.contains("alice@pve, bob@pve"));
    }

    #[test]
    fn a_read_only_custom_role_is_left_alone() {
        assert!(custom_roles(&access()).is_empty());
    }

    #[test]
    fn a_custom_role_with_sys_modify_is_not_read_only() {
        let mut a = access();
        a.roles
            .push(json!({ "roleid": "Halfway", "privs": "Sys.Audit,Sys.Modify", "special": 0 }));
        let out = custom_roles(&a);
        assert_eq!(out.len(), 1);
        assert!(out[0].detail.contains("Sys.Modify"));
    }

    #[test]
    fn root_without_a_factor_outranks_a_service_account_without_one() {
        let mut a = access();
        a.users.push(json!({ "userid": "svc@pve", "enable": 1 }));
        let out = users(&a, 0);
        let root = out.iter().find(|f| f.subject == "user/root@pam").unwrap();
        let svc = out.iter().find(|f| f.subject == "user/svc@pve").unwrap();
        assert_eq!(root.severity, Severity::High);
        assert_eq!(svc.severity, Severity::Medium);
    }

    #[test]
    fn a_registered_factor_that_is_disabled_is_not_a_factor() {
        let mut a = access();
        a.tfa = vec![tfa_row(
            "root@pam",
            json!([{ "type": "totp", "enable": 0, "id": "x" }]),
        )];
        let out = users(&a, 0);
        assert!(out.iter().any(|f| f.id == "access.tfa-all-disabled"));
        assert!(!out.iter().any(|f| f.id == "access.no-tfa"));
    }

    #[test]
    fn recovery_keys_alone_are_told_apart_from_a_real_factor() {
        let mut a = access();
        a.tfa = vec![tfa_row(
            "root@pam",
            json!([{ "type": "recovery", "enable": 1, "id": "r" }]),
        )];
        assert!(users(&a, 0)
            .iter()
            .any(|f| f.id == "access.tfa-recovery-only"));

        a.tfa = vec![tfa_row(
            "root@pam",
            json!([
                { "type": "recovery", "enable": 1, "id": "r" },
                { "type": "webauthn", "enable": 1, "id": "w" }
            ]),
        )];
        let out = users(&a, 0);
        assert!(!out.iter().any(|f| f.id.starts_with("access.tfa")));
        assert!(!out.iter().any(|f| f.id == "access.no-tfa"));
    }

    #[test]
    fn a_realm_that_enforces_a_factor_settles_it_for_every_account_in_it() {
        let mut a = access();
        a.realms = vec![json!({ "realm": "pam", "type": "pam", "tfa": "type=totp" })];
        assert!(!users(&a, 0).iter().any(|f| f.id == "access.no-tfa"));
    }

    #[test]
    fn an_active_lockout_is_reported_while_it_lasts() {
        let mut a = access();
        a.tfa = vec![json!({
            "userid": "root@pam",
            "entries": [{ "type": "totp", "enable": 1, "id": "t" }],
            "tfa-locked-until": 2_000
        })];
        assert!(users(&a, 1_000).iter().any(|f| f.id == "access.tfa-locked"));
        assert!(!users(&a, 3_000).iter().any(|f| f.id == "access.tfa-locked"));
    }

    #[test]
    fn a_grant_to_something_that_does_not_exist_is_a_name_waiting_to_be_reused() {
        let mut a = access();
        a.acl = vec![json!({
            "path": "/vms", "type": "user", "ugid": "gone@pve",
            "roleid": "MlabAudit", "propagate": 1
        })];
        let out = acl_hygiene(&a);
        assert!(out.iter().any(|f| f.id == "access.acl-orphan"));
    }

    #[test]
    fn a_token_grant_is_not_called_orphan_when_the_token_list_was_refused() {
        let mut a = access();
        a.tokens_readable = false;
        a.acl = vec![json!({
            "path": "/", "type": "token", "ugid": "svc@pve!ci",
            "roleid": "MlabAudit", "propagate": 1
        })];
        assert!(!acl_hygiene(&a).iter().any(|f| f.id == "access.acl-orphan"));
    }

    #[test]
    fn a_deeper_grant_is_reported_as_replacing_the_inherited_one() {
        let mut a = access();
        a.users.push(json!({ "userid": "ops@pve", "enable": 1 }));
        a.acl = vec![
            json!({ "path": "/", "type": "user", "ugid": "ops@pve", "roleid": "Administrator", "propagate": 1 }),
            json!({ "path": "/vms/150", "type": "user", "ugid": "ops@pve", "roleid": "MlabAudit", "propagate": 1 }),
        ];
        let out = acl_hygiene(&a);
        let f = out.iter().find(|f| f.id == "access.acl-override").unwrap();
        assert!(f.title.contains("replaces the inherited Administrator"));
    }

    #[test]
    fn the_same_role_repeated_deeper_is_not_an_override() {
        let mut a = access();
        a.users.push(json!({ "userid": "ops@pve", "enable": 1 }));
        a.acl = vec![
            json!({ "path": "/", "type": "user", "ugid": "ops@pve", "roleid": "MlabAudit", "propagate": 1 }),
            json!({ "path": "/vms", "type": "user", "ugid": "ops@pve", "roleid": "MlabAudit", "propagate": 1 }),
        ];
        assert!(!acl_hygiene(&a)
            .iter()
            .any(|f| f.id == "access.acl-override"));
    }

    #[test]
    fn a_sync_job_that_keeps_permissions_is_the_one_that_matters() {
        let mut a = access();
        a.realm_sync = vec![json!({
            "id": "s1", "realm": "ldap", "enabled": 1,
            "remove-vanished": "entry;properties", "last-run": 1_700_000_000i64
        })];
        let out = realm_sync(&a);
        assert!(out.iter().any(|f| f.id == "access.realm-sync-keeps-acl"));

        a.realm_sync = vec![json!({
            "id": "s1", "realm": "ldap", "enabled": 1,
            "remove-vanished": "entry;acl;properties", "last-run": 1_700_000_000i64
        })];
        assert!(realm_sync(&a).is_empty());
    }

    #[test]
    fn an_empty_group_that_still_holds_a_grant_is_a_loaded_gun() {
        let mut a = access();
        a.groups = vec![json!({ "groupid": "ops", "users": "" })];
        a.acl = vec![json!({
            "path": "/", "type": "group", "ugid": "ops",
            "roleid": "MlabAudit", "propagate": 1
        })];
        assert!(users(&a, 0)
            .iter()
            .any(|f| f.id == "access.empty-group-grant"));
    }

    #[test]
    fn an_unreadable_token_list_is_an_admission_not_a_pass() {
        let a = Access {
            tokens_readable: false,
            ..access()
        };
        let out = tokens(&a, 0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::Unreadable);
    }

    #[test]
    fn a_token_without_privsep_or_expiry_is_two_separate_findings() {
        let mut a = access();
        a.tokens_readable = true;
        a.tokens = vec![json!({ "userid": "svc@pve", "tokenid": "ci", "privsep": 0, "expire": 0 })];
        let out = tokens(&a, 1_700_000_000);
        assert!(out.iter().any(|f| f.id == "access.token-full-privileges"));
        assert!(out.iter().any(|f| f.id == "access.token-no-expiry"));
    }
}
