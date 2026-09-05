//! One pass over everything the token can read.
//!
//! Two rules hold this module together. Nothing here judges: it fetches and
//! shapes, and [`crate::checks`] decides what any of it means. And nothing
//! here fails a run: a route the token is refused, or a route this version of
//! Proxmox does not serve, is recorded in [`Fetcher::unreadable`] so a check
//! can say "not readable" instead of "clean".

use std::collections::BTreeMap;

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;

use crate::pve::{esc, Client};
use crate::ui;

/// A route that answered with something other than data, and why.
#[derive(Debug, Clone, Serialize)]
pub struct Unreadable {
    pub path: String,
    pub reason: String,
}

/// A client plus the record of what it could not read.
pub struct Fetcher<'a> {
    c: &'a Client,
    pub unreadable: Vec<Unreadable>,
}

impl<'a> Fetcher<'a> {
    pub fn new(c: &'a Client) -> Self {
        Fetcher {
            c,
            unreadable: Vec::new(),
        }
    }

    pub fn client(&self) -> &Client {
        self.c
    }

    /// One object, or `Null` with the failure recorded.
    pub async fn get(&mut self, path: &str) -> Value {
        match self.c.get(path).await {
            Ok(v) => v,
            Err(e) => {
                self.note(path, &e);
                Value::Null
            }
        }
    }

    /// One list, or an empty one with the failure recorded.
    pub async fn list(&mut self, path: &str) -> Vec<Value> {
        match self.c.list(path).await {
            Ok(v) => v,
            Err(e) => {
                self.note(path, &e);
                Vec::new()
            }
        }
    }

    fn note(&mut self, path: &str, e: &anyhow::Error) {
        let reason = e.to_string().lines().next().unwrap_or("").to_string();
        self.unreadable.push(Unreadable {
            path: path.to_string(),
            reason,
        });
    }
}

/// One guest, with the parts of it a check needs.
#[derive(Debug, Clone, Serialize)]
pub struct Guest {
    pub node: String,
    pub vmid: i64,
    /// `qemu` or `lxc`.
    pub kind: String,
    pub name: String,
    pub status: String,
    pub template: bool,
    pub config: Value,
    pub firewall: Value,
    pub firewall_rules: Vec<Value>,
    /// The guest's own IP sets, each with its members already resolved.
    pub firewall_ipsets: BTreeMap<String, Vec<Value>>,
    pub snapshots: Vec<Value>,
    /// Config keys staged for the next start. `config` is what is stored; a
    /// running guest may be enforcing something else entirely.
    pub pending: Vec<String>,
    /// What the QEMU guest agent answered, when there is one and it replies.
    pub agent: Agent,
}

/// The guest agent, and whether it is more than a line in a config file.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Agent {
    /// `enabled=1` in the guest configuration.
    pub configured: bool,
    /// Answered a read. `false` with `configured` true is the interesting case.
    pub alive: bool,
    pub osinfo: Value,
    pub hostname: Value,
    pub interfaces: Vec<Value>,
    pub users: Vec<Value>,
}

impl Guest {
    /// `vm/150` or `ct/104`, the subject string every finding uses.
    pub fn subject(&self) -> String {
        let prefix = if self.kind == "lxc" { "ct" } else { "vm" };
        format!("{prefix}/{}", self.vmid)
    }

    pub fn label(&self) -> String {
        if self.name.is_empty() {
            self.subject()
        } else {
            format!("{} ({})", self.name, self.subject())
        }
    }

    /// The `netN` entries of the config, parsed, in index order.
    pub fn nets(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        if let Some(map) = self.config.as_object() {
            let mut keys: Vec<&String> = map
                .keys()
                .filter(|k| k.starts_with("net") && k[3..].chars().all(|c| c.is_ascii_digit()))
                .collect();
            keys.sort();
            for k in keys {
                if let Some(v) = map[k].as_str() {
                    out.push((k.clone(), v.to_string()));
                }
            }
        }
        out
    }
}

/// One node and the host-level state a check needs.
#[derive(Debug, Clone, Serialize)]
pub struct Node {
    pub name: String,
    pub status: Value,
    pub version: Value,
    pub subscription: Value,
    pub services: Vec<Value>,
    pub network: Vec<Value>,
    pub dns: Value,
    pub time: Value,
    pub certificates: Vec<Value>,
    pub repositories: Value,
    pub disks: Vec<Value>,
    /// Host PCI devices, each with the IOMMU group that decides whether two
    /// guests holding one can reach into each other.
    pub pci: Vec<Value>,
    /// LVM thin pools, which corrupt what they hold when they fill — and whose
    /// metadata fills before the data does.
    pub thin_pools: Vec<Value>,
    pub zfs_pools: Vec<Value>,
    /// `/etc/hosts`, which is how a node resolves its own cluster name.
    pub hosts: Value,
    pub firewall: Value,
    pub firewall_rules: Vec<Value>,
    /// `None` when the token lacks `Sys.Modify`, which is the usual case.
    pub updates: Option<Vec<Value>>,
    /// Installed package versions. Unlike the update list, this one needs no
    /// privilege beyond the audit role.
    pub packages: Vec<Value>,
}

/// Users, tokens and the ACL tree.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Access {
    pub users: Vec<Value>,
    /// Every token of every user, flattened, each carrying its `userid`.
    /// Empty and `tokens_readable == false` when the token lacks `User.Modify`.
    pub tokens: Vec<Value>,
    pub tokens_readable: bool,
    pub acl: Vec<Value>,
    pub roles: Vec<Value>,
    pub realms: Vec<Value>,
    pub groups: Vec<Value>,
    /// One row per user that registered a factor, each carrying its `entries`
    /// and the current lockout state.
    pub tfa: Vec<Value>,
    /// Directory synchronisation jobs, which decide what happens to a PVE
    /// account when the user disappears from the directory.
    pub realm_sync: Vec<Value>,
}

/// The cluster-wide firewall objects.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Firewall {
    pub options: Value,
    pub rules: Vec<Value>,
    pub groups: Vec<Value>,
    /// The rules of each security group, by group name. A rule of type
    /// `group` is a reference; without these, its contents are a black box.
    pub group_rules: BTreeMap<String, Vec<Value>>,
    pub ipsets: Vec<Value>,
    /// The members of each IP set, by set name.
    pub ipset_members: BTreeMap<String, Vec<Value>>,
    pub aliases: Vec<Value>,
    /// Which aliases and IP sets the rules actually reference.
    pub refs: Vec<Value>,
}

/// Everything one run collected.
#[derive(Debug, Clone, Serialize)]
pub struct Inventory {
    pub collected: String,
    pub endpoint: String,
    pub version: Value,
    pub cluster_status: Vec<Value>,
    pub resources: Vec<Value>,
    pub options: Value,
    pub nodes: Vec<Node>,
    pub guests: Vec<Guest>,
    pub storages: Vec<Value>,
    pub backup_jobs: Vec<Value>,
    pub not_backed_up: Vec<Value>,
    pub replication: Vec<Value>,
    pub ha_resources: Vec<Value>,
    pub metrics_servers: Vec<Value>,
    pub notification_targets: Vec<Value>,
    pub sdn_zones: Vec<Value>,
    pub sdn_vnets: Vec<Value>,
    /// The corosync configuration, `Null` on a standalone node.
    pub totem: Value,
    /// The most recent cluster tasks, newest first.
    pub tasks: Vec<Value>,
    /// The cluster log: authentication events, task starts and ends, with the
    /// user behind each. The only place a failed login is visible.
    pub cluster_log: Vec<Value>,
    /// Storage as each node sees it, with capacity.
    pub storage_status: Vec<Value>,
    /// The backup files that actually exist, whatever the jobs claim.
    pub backups: Vec<Value>,
    /// Corosync's third vote, if there is one.
    pub qdevice: Value,
    /// HA as the manager currently sees it.
    pub ha_status: Vec<Value>,
    pub access: Access,
    pub firewall: Firewall,
    pub permissions: Value,
    pub unreadable: Vec<Unreadable>,
}

/// The node names of the cluster.
pub async fn node_names(f: &mut Fetcher<'_>) -> Vec<String> {
    f.list("/nodes")
        .await
        .iter()
        .filter_map(|n| n.get("node").and_then(Value::as_str).map(str::to_string))
        .collect()
}

/// One node, with everything host-level a check reads.
pub async fn node(f: &mut Fetcher<'_>, name: &str) -> Node {
    node_inner(f, name, true).await
}

/// The same without the pending-update list, for the commands that do not
/// report on patching: asking for it would only record a refusal they cannot
/// act on and did not ask about.
pub async fn node_without_updates(f: &mut Fetcher<'_>, name: &str) -> Node {
    node_inner(f, name, false).await
}

async fn node_inner(f: &mut Fetcher<'_>, name: &str, want_updates: bool) -> Node {
    let n = esc(name);
    // Pending updates need Sys.Modify, which a read-only token has no business
    // holding; ask once, and record the refusal rather than the packages.
    let updates = if !want_updates {
        None
    } else {
        match f.client().get(&format!("/nodes/{n}/apt/update")).await {
            Ok(Value::Array(rows)) => Some(rows),
            Ok(_) => None,
            Err(e) => {
                f.note(&format!("/nodes/{n}/apt/update"), &e);
                None
            }
        }
    };

    Node {
        name: name.to_string(),
        status: f.get(&format!("/nodes/{n}/status")).await,
        version: f.get(&format!("/nodes/{n}/version")).await,
        subscription: f.get(&format!("/nodes/{n}/subscription")).await,
        services: f.list(&format!("/nodes/{n}/services")).await,
        network: f.list(&format!("/nodes/{n}/network")).await,
        dns: f.get(&format!("/nodes/{n}/dns")).await,
        time: f.get(&format!("/nodes/{n}/time")).await,
        certificates: f.list(&format!("/nodes/{n}/certificates/info")).await,
        repositories: f.get(&format!("/nodes/{n}/apt/repositories")).await,
        disks: f.list(&format!("/nodes/{n}/disks/list")).await,
        pci: f.list(&format!("/nodes/{n}/hardware/pci")).await,
        thin_pools: f.list(&format!("/nodes/{n}/disks/lvmthin")).await,
        zfs_pools: f.list(&format!("/nodes/{n}/disks/zfs")).await,
        hosts: f.get(&format!("/nodes/{n}/hosts")).await,
        firewall: f.get(&format!("/nodes/{n}/firewall/options")).await,
        firewall_rules: f.list(&format!("/nodes/{n}/firewall/rules")).await,
        updates,
        packages: f.list(&format!("/nodes/{n}/apt/versions")).await,
    }
}

/// Every guest of one node, configuration included.
pub async fn guests_of(f: &mut Fetcher<'_>, node: &str) -> Vec<Guest> {
    let n = esc(node);
    let mut out = Vec::new();

    for kind in ["qemu", "lxc"] {
        for row in f.list(&format!("/nodes/{n}/{kind}")).await {
            let Some(vmid) = row.get("vmid").and_then(Value::as_i64) else {
                continue;
            };
            let base = format!("/nodes/{n}/{kind}/{vmid}");
            out.push(Guest {
                node: node.to_string(),
                vmid,
                kind: kind.to_string(),
                name: row
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                status: row
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                template: row.get("template").and_then(Value::as_i64) == Some(1),
                config: f.get(&format!("{base}/config")).await,
                firewall: f.get(&format!("{base}/firewall/options")).await,
                firewall_rules: f.list(&format!("{base}/firewall/rules")).await,
                // One call to learn there are none, which is the usual answer;
                // the members are only fetched for a guest that has some.
                firewall_ipsets: guest_ipsets(f, &base).await,
                snapshots: f.list(&format!("{base}/snapshot")).await,
                pending: pending_keys(f, &base).await,
                agent: agent(f, &base, kind, &row).await,
            });
        }
    }
    out
}

/// The config keys a running guest has not picked up yet.
///
/// `/pending` returns every key with, when they differ, the stored value and
/// the one in force. A key carrying `pending` or marked for deletion is one
/// the guest is not currently honouring.
async fn pending_keys(f: &mut Fetcher<'_>, base: &str) -> Vec<String> {
    f.list(&format!("{base}/pending"))
        .await
        .iter()
        .filter(|r| r.get("pending").is_some() || r.get("delete").is_some())
        .filter_map(|r| r.get("key").and_then(Value::as_str).map(str::to_string))
        .collect()
}

/// Ask the guest agent, once, and only fan out when something answers.
///
/// The agent is a read into the guest that costs nothing to the network: no
/// port, no credential, no packet. What it returns is the guest describing
/// itself, which is an inventory rather than a verification.
async fn agent(f: &mut Fetcher<'_>, base: &str, kind: &str, row: &Value) -> Agent {
    let mut a = Agent::default();
    if kind != "qemu" {
        return a;
    }
    // The flag lives in the config as `enabled=1[,...]`.
    let cfg = f
        .client()
        .get(&format!("{base}/config"))
        .await
        .unwrap_or(Value::Null);
    let raw = cfg
        .get("agent")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    a.configured = raw.split(',').any(|p| {
        let p = p.trim();
        p == "1" || p == "enabled=1"
    });
    if !a.configured || row.get("status").and_then(Value::as_str) != Some("running") {
        return a;
    }

    // One probe. A stopped or absent agent answers 500, which is the answer.
    if f.client().get(&format!("{base}/agent/info")).await.is_err() {
        return a;
    }
    a.alive = true;
    a.osinfo = f.get(&format!("{base}/agent/get-osinfo")).await;
    a.hostname = f.get(&format!("{base}/agent/get-host-name")).await;
    a.interfaces = match f.get(&format!("{base}/agent/network-get-interfaces")).await {
        Value::Object(o) => o
            .get("result")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        Value::Array(v) => v,
        _ => Vec::new(),
    };
    a.users = match f.get(&format!("{base}/agent/get-users")).await {
        Value::Object(o) => o
            .get("result")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        Value::Array(v) => v,
        _ => Vec::new(),
    };
    a
}

/// The IP sets of one guest, with their members.
async fn guest_ipsets(f: &mut Fetcher<'_>, base: &str) -> BTreeMap<String, Vec<Value>> {
    let mut out = BTreeMap::new();
    for set in f.list(&format!("{base}/firewall/ipset")).await {
        let Some(name) = set.get("name").and_then(Value::as_str) else {
            continue;
        };
        let members = f
            .list(&format!("{base}/firewall/ipset/{}", esc(name)))
            .await;
        out.insert(name.to_string(), members);
    }
    out
}

/// Users, their tokens, the ACL tree and the realms.
pub async fn access(f: &mut Fetcher<'_>) -> Access {
    let users = f.list("/access/users").await;

    // A token list belongs to its user and needs User.Modify on that user's
    // group; the first refusal settles it for every user.
    let mut tokens = Vec::new();
    let mut tokens_readable = true;
    for u in &users {
        let Some(id) = u.get("userid").and_then(Value::as_str) else {
            continue;
        };
        let path = format!("/access/users/{}/token", esc(id));
        match f.client().list(&path).await {
            Ok(rows) => {
                for mut t in rows {
                    if let Some(o) = t.as_object_mut() {
                        o.insert("userid".into(), Value::String(id.to_string()));
                    }
                    tokens.push(t);
                }
            }
            Err(e) => {
                if tokens_readable {
                    f.note(&path, &e);
                }
                tokens_readable = false;
            }
        }
    }

    Access {
        users,
        tokens,
        tokens_readable,
        acl: f.list("/access/acl").await,
        roles: f.list("/access/roles").await,
        realms: f.list("/access/domains").await,
        groups: f.list("/access/groups").await,
        tfa: f.list("/access/tfa").await,
        realm_sync: f.list("/cluster/jobs/realm-sync").await,
    }
}

/// The cluster-wide firewall configuration, security groups and IP sets
/// included: a rule that references one of those says nothing on its own.
pub async fn firewall(f: &mut Fetcher<'_>) -> Firewall {
    let options = f.get("/cluster/firewall/options").await;
    let rules = f.list("/cluster/firewall/rules").await;
    let groups = f.list("/cluster/firewall/groups").await;
    let ipsets = f.list("/cluster/firewall/ipset").await;

    let mut group_rules = BTreeMap::new();
    for g in &groups {
        let Some(name) = g.get("group").and_then(Value::as_str) else {
            continue;
        };
        let rows = f
            .list(&format!("/cluster/firewall/groups/{}", esc(name)))
            .await;
        group_rules.insert(name.to_string(), rows);
    }

    let mut ipset_members = BTreeMap::new();
    for set in &ipsets {
        let Some(name) = set.get("name").and_then(Value::as_str) else {
            continue;
        };
        let rows = f
            .list(&format!("/cluster/firewall/ipset/{}", esc(name)))
            .await;
        ipset_members.insert(name.to_string(), rows);
    }

    Firewall {
        options,
        rules,
        groups,
        group_rules,
        ipsets,
        ipset_members,
        aliases: f.list("/cluster/firewall/aliases").await,
        refs: f.list("/cluster/firewall/refs").await,
    }
}

/// Everything, in one pass, behind a progress line that names the step.
pub async fn all(c: &Client) -> Result<Inventory> {
    let spinner = ui::Spinner::start("Reading the cluster");
    let mut f = Fetcher::new(c);

    let version = f.get("/version").await;
    let cluster_status = f.list("/cluster/status").await;
    let resources = f.list("/cluster/resources").await;
    let options = f.get("/cluster/options").await;
    let permissions = f.get("/access/permissions").await;

    spinner.set("Reading storage and backup");
    let storages = f.list("/storage").await;
    let backup_jobs = f.list("/cluster/backup").await;
    let not_backed_up = f.list("/cluster/backup-info/not-backed-up").await;
    let replication = f.list("/cluster/replication").await;

    spinner.set("Reading the firewall");
    let firewall = firewall(&mut f).await;

    spinner.set("Reading access control");
    let access = access(&mut f).await;

    spinner.set("Reading cluster services");
    let ha_resources = f.list("/cluster/ha/resources").await;
    let metrics_servers = f.list("/cluster/metrics/server").await;
    let notification_targets = f.list("/cluster/notifications/targets").await;
    let sdn_zones = f.list("/cluster/sdn/zones").await;
    let sdn_vnets = f.list("/cluster/sdn/vnets").await;
    let totem = f.get("/cluster/config/totem").await;
    let tasks = f.list("/cluster/tasks").await;
    let cluster_log = f.list("/cluster/log").await;
    let qdevice = f.get("/cluster/config/qdevice").await;
    let ha_status = f.list("/cluster/ha/status/current").await;

    let names = node_names(&mut f).await;
    let mut nodes = Vec::new();
    let mut guests = Vec::new();
    for name in &names {
        spinner.set(format!("Reading node {name}"));
        nodes.push(node(&mut f, name).await);
        spinner.set(format!("Reading the guests of {name}"));
        guests.extend(guests_of(&mut f, name).await);
    }

    spinner.set("Reading what is on the storages");
    let mut storage_status = Vec::new();
    let mut backups = Vec::new();
    for name in &names {
        for st in f.list(&format!("/nodes/{}/storage", esc(name))).await {
            let Some(id) = st.get("storage").and_then(Value::as_str) else {
                continue;
            };
            let mut row = st.clone();
            if let Some(o) = row.as_object_mut() {
                o.insert("node".into(), Value::String(name.clone()));
            }
            let holds_backups = st
                .get("content")
                .and_then(Value::as_str)
                .map(|c| c.split(',').any(|x| x.trim() == "backup"))
                .unwrap_or(false);
            storage_status.push(row);

            // A job is an intention; these are the files. Only ask storages
            // that accept backups, and only those the node reports as active.
            if holds_backups && st.get("active").and_then(Value::as_i64) == Some(1) {
                let path = format!("/nodes/{}/storage/{}/content", esc(name), esc(id));
                let query = [("content".to_string(), "backup".to_string())];
                if let Ok(Value::Array(rows)) = f
                    .client()
                    .request(reqwest::Method::GET, &path, &query, None)
                    .await
                {
                    for mut b in rows {
                        if let Some(o) = b.as_object_mut() {
                            o.insert("storage".into(), Value::String(id.to_string()));
                            o.insert("node".into(), Value::String(name.clone()));
                        }
                        backups.push(b);
                    }
                }
            }
        }
    }

    spinner.clear();

    Ok(Inventory {
        collected: crate::pve::iso8601(now()),
        endpoint: c.base().to_string(),
        version,
        cluster_status,
        resources,
        options,
        nodes,
        guests,
        storages,
        backup_jobs,
        not_backed_up,
        replication,
        ha_resources,
        metrics_servers,
        notification_targets,
        sdn_zones,
        sdn_vnets,
        totem,
        tasks,
        cluster_log,
        storage_status,
        backups,
        qdevice,
        ha_status,
        access,
        firewall,
        permissions,
        unreadable: f.unreadable,
    })
}

/// Seconds since the epoch.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
