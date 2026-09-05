//! Guest hardening: what a VM or container is allowed to touch on its host.
//!
//! Most of this lives in one or two words of a property string. A container
//! is either `unprivileged` or it is not; a VM either carries `args:` or it
//! does not. That is what makes it worth reading every config in one pass.

use crate::checks::{flag, i, prop, propstring, s, Finding, Severity};
use crate::collect::Guest;

/// How old a snapshot has to be before it is worth mentioning.
const STALE_SNAPSHOT_DAYS: i64 = 90;

/// CPU flags that turn off a side-channel mitigation when negated.
const MITIGATIONS: [&str; 6] = [
    "spec-ctrl",
    "md-clear",
    "ibpb",
    "ssbd",
    "virt-ssbd",
    "amd-ssbd",
];

pub fn all(g: &Guest, now: i64) -> Vec<Finding> {
    let mut out = Vec::new();
    if g.kind == "lxc" {
        out.extend(container(g));
    } else {
        out.extend(vm(g));
    }
    out.extend(common(g));
    out.extend(snapshots(g, now));
    out.extend(state(g));
    out
}

/// What the guest is doing, as opposed to what its configuration says.
fn state(g: &Guest) -> Vec<Finding> {
    let mut out = Vec::new();
    let subject = g.subject();

    // Everything else in this module grades the stored configuration. When a
    // key is staged, the running guest is enforcing something else, and the
    // rest of this report describes a machine that does not exist yet.
    if !g.pending.is_empty() {
        out.push(
            Finding::new(
                "guest.pending-changes",
                Severity::Medium,
                &subject,
                format!(
                    "{} has {} setting(s) that only take effect at the next start",
                    g.label(),
                    g.pending.len()
                ),
            )
            .detail(format!(
                "{}. Every other finding about this guest reads the stored configuration, so \
                 for these keys it describes what will run, not what is running.",
                g.pending.join(", ")
            )),
        );
    }

    let lock = s(&g.config, "lock");
    if !lock.is_empty() {
        out.push(
            Finding::new(
                "guest.locked",
                Severity::Medium,
                &subject,
                format!("{} is locked ({lock})", g.label()),
            )
            .detail(
                "A lock left behind by an interrupted backup, migration or clone blocks every \
                 later operation on this guest, including the next backup.",
            ),
        );
    }

    // An agent configured and not answering is worse than no agent: the backup
    // believes it can quiesce the filesystem and cannot.
    if g.agent.configured && !g.agent.alive && g.status == "running" {
        out.push(
            Finding::new(
                "guest.agent-not-running",
                Severity::Medium,
                &subject,
                format!("{} declares a guest agent that does not answer", g.label()),
            )
            .detail(
                "With `agent: enabled=1` Proxmox asks the agent to freeze the filesystem before \
                 a snapshot backup. No agent means no freeze, and a backup taken from a live \
                 filesystem that the configuration says was quiesced.",
            )
            .remedy("Install and start qemu-guest-agent inside the guest, or set `agent: 0`."),
        );
    }

    if !g.agent.users.is_empty() {
        let names: Vec<String> = g
            .agent
            .users
            .iter()
            .map(|u| s(u, "user"))
            .filter(|u| !u.is_empty())
            .collect();
        out.push(
            Finding::new(
                "guest.logged-in-users",
                Severity::Info,
                &subject,
                format!("{} has {} session(s) open", g.label(), names.len()),
            )
            .detail(format!(
                "{}. Reported by the agent, which is the guest describing itself.",
                names.join(", ")
            )),
        );
    }
    out
}

/// Container isolation: the privileged flag and everything that loosens it.
fn container(g: &Guest) -> Vec<Finding> {
    let mut out = Vec::new();
    let subject = g.subject();
    let label = g.label();
    let cfg = &g.config;

    // The field is only written when it is 1, and an old container restored
    // from a backup keeps whatever it had, so absence means privileged.
    let privileged = !flag(cfg, "unprivileged", false);
    let features = propstring(&s(cfg, "features"), "");
    let on = |k: &str| prop(&features, k) == Some("1");

    if privileged {
        out.push(
            Finding::new(
                "guest.privileged-container",
                Severity::High,
                &subject,
                format!("{label} is a privileged container"),
            )
            .detail(
                "root inside the container is root on the host: the user namespace is not \
                 remapped, so a kernel escape lands with full host privileges.",
            )
            .remedy("Rebuild it as unprivileged; the flag cannot be flipped safely on an existing rootfs."),
        );
    }

    if privileged && on("nesting") {
        out.push(
            Finding::new(
                "guest.privileged-nesting",
                Severity::Critical,
                &subject,
                format!("{label} is privileged and allows nesting"),
            )
            .detail(
                "Nesting exposes /proc and /sys interfaces the container would not otherwise \
                 reach. Combined with privileged mode, this is the documented escape path.",
            ),
        );
    } else if on("nesting") {
        out.push(
            Finding::new(
                "guest.container-nesting",
                Severity::Low,
                &subject,
                format!("{label} allows nesting"),
            )
            .detail(
                "Expected for a container running Docker or systemd-nspawn; noted, not condemned.",
            ),
        );
    }

    for (feature, severity, why) in [
        (
            "keyctl",
            Severity::Medium,
            "gives the container its own kernel keyring, which widens the syscall surface",
        ),
        (
            "mknod",
            Severity::Medium,
            "lets the container create device nodes",
        ),
        (
            "fuse",
            Severity::Low,
            "allows FUSE mounts inside the container",
        ),
        (
            "force_rw_sys",
            Severity::Medium,
            "mounts /sys read-write, which is normally read-only for a reason",
        ),
    ] {
        if on(feature) {
            out.push(
                Finding::new(
                    "guest.container-feature",
                    severity,
                    &subject,
                    format!("{label} has the {feature} feature"),
                )
                .detail(format!("It {why}.")),
            );
        }
    }

    if let Some(fs) = prop(&features, "mount") {
        out.push(
            Finding::new(
                "guest.container-mount",
                Severity::High,
                &subject,
                format!("{label} may mount {fs} itself"),
            )
            .detail(
                "In-container mounting of a real filesystem type hands the kernel parser an \
                 image the container controls.",
            ),
        );
    }

    // A console that spawns a shell asks for nothing: whoever reaches it is
    // root inside the container without authenticating.
    if s(cfg, "cmode") == "shell" {
        out.push(
            Finding::new(
                "guest.console-without-login",
                Severity::Medium,
                &subject,
                format!("{label} opens a shell on its console instead of a login"),
            )
            .detail(
                "`cmode: shell` skips getty entirely. Console access already needs VM.Console, \
                 but from there there is no second step.",
            ),
        );
    }

    // The uid remapping is what makes an unprivileged container unprivileged.
    for (key, raw) in indexed(g, "mp").into_iter().chain(
        std::iter::once(("rootfs".to_string(), s(cfg, "rootfs"))).filter(|(_, v)| !v.is_empty()),
    ) {
        let p = propstring(&raw, "volume");
        if let Some(map) = prop(&p, "idmap") {
            out.push(
                Finding::new(
                    "guest.custom-idmap",
                    Severity::Medium,
                    &subject,
                    format!("{label} overrides the uid mapping on {key}"),
                )
                .detail(format!(
                    "`idmap={map}` — the remapping is what keeps root in the container from \
                     being root on the host for these files."
                )),
            );
        }
    }

    // Bind mounts: a host path rather than a storage volume.
    for (key, raw) in indexed(g, "mp") {
        let p = propstring(&raw, "volume");
        let volume = prop(&p, "volume").unwrap_or_default();
        if volume.starts_with('/') {
            let ro = prop(&p, "ro") == Some("1");
            out.push(
                Finding::new(
                    "guest.bind-mount",
                    if ro { Severity::Medium } else { Severity::High },
                    &subject,
                    format!("{label} bind-mounts the host path {volume}"),
                )
                .detail(format!(
                    "{key} maps a host directory into the container{}.",
                    if ro { ", read-only" } else { ", writable" }
                )),
            );

            // A writable host path mounted without these lets the container
            // plant a setuid binary the host will honour.
            let opts = prop(&p, "mountoptions").unwrap_or_default();
            let missing: Vec<&str> = ["nosuid", "nodev", "noexec"]
                .into_iter()
                .filter(|o| !opts.split(';').any(|x| x.trim() == *o))
                .collect();
            if !ro && !missing.is_empty() {
                out.push(
                    Finding::new(
                        "guest.bind-mount-options",
                        Severity::Medium,
                        &subject,
                        format!("{label} mounts {volume} without {}", missing.join(", ")),
                    )
                    .detail(
                        "Without nosuid and nodev, a file the container creates in that \
                         directory keeps its setuid bit and its device semantics on the host.",
                    ),
                );
            }
        }
    }

    for (key, raw) in indexed(g, "dev") {
        let p = propstring(&raw, "path");
        let path = prop(&p, "path").unwrap_or_default();
        out.push(
            Finding::new(
                "guest.device-passthrough",
                Severity::Medium,
                &subject,
                format!("{label} has host device {path} passed through"),
            )
            .detail(format!(
                "{key} exposes a host device node to the container."
            )),
        );
    }

    out
}

/// Virtual machine hardening: the escapes that live in the QEMU command line.
fn vm(g: &Guest) -> Vec<Finding> {
    let mut out = Vec::new();
    let subject = g.subject();
    let label = g.label();
    let cfg = &g.config;

    let args = s(cfg, "args");
    if !args.is_empty() {
        out.push(
            Finding::new(
                "guest.raw-args",
                Severity::High,
                &subject,
                format!("{label} passes raw arguments to QEMU"),
            )
            .detail(format!(
                "`args: {args}` is appended to the kvm command line and is invisible to every \
                 other setting in the configuration."
            )),
        );
    }

    for (key, raw) in indexed(g, "hostpci") {
        let p = propstring(&raw, "host");
        let dev = prop(&p, "host")
            .or_else(|| prop(&p, "mapping"))
            .unwrap_or_default();
        out.push(
            Finding::new(
                "guest.pci-passthrough",
                Severity::Medium,
                &subject,
                format!("{label} owns host PCI device {dev}"),
            )
            .detail(format!(
                "{key} gives the guest a DMA-capable device. Isolation then rests on the IOMMU \
                 group, not on QEMU."
            )),
        );
    }

    for (key, raw) in indexed(g, "usb") {
        let p = propstring(&raw, "host");
        if let Some(host) = prop(&p, "host") {
            if host != "spice" {
                out.push(
                    Finding::new(
                        "guest.usb-passthrough",
                        Severity::Low,
                        &subject,
                        format!("{label} owns host USB device {host}"),
                    )
                    .detail(format!("{key} attaches a physical port to the guest.")),
                );
            }
        }
    }

    for (key, raw) in indexed(g, "virtiofs") {
        let p = propstring(&raw, "dirid");
        let dir = prop(&p, "dirid").unwrap_or_default();
        out.push(
            Finding::new(
                "guest.virtiofs-share",
                Severity::Medium,
                &subject,
                format!("{label} shares the host directory mapping {dir}"),
            )
            .detail(format!("{key} exposes a host filesystem to the guest.")),
        );
    }

    if !s(cfg, "ivshmem").is_empty() {
        out.push(
            Finding::new(
                "guest.shared-memory",
                Severity::Medium,
                &subject,
                format!("{label} has inter-VM shared memory"),
            )
            .detail(
                "`ivshmem` is a memory region shared with the host or with another VM: a channel \
                 no firewall sees.",
            ),
        );
    }

    if !s(cfg, "cipassword").is_empty() {
        out.push(
            Finding::new(
                "guest.cloudinit-password",
                Severity::Medium,
                &subject,
                format!("{label} carries a cloud-init password"),
            )
            .detail(
                "`cipassword` is stored in the guest config and handed to the instance at boot; \
                 SSH keys do the same job without a reusable secret.",
            ),
        );
    }

    // A negated mitigation flag is a deliberate decision to run faster and
    // exposed, and it survives every kernel update on the host.
    let cpu = propstring(&s(cfg, "cpu"), "cputype");
    if let Some(flags) = prop(&cpu, "flags") {
        let off: Vec<&str> = MITIGATIONS
            .iter()
            .copied()
            .filter(|m| flags.split(';').any(|f| f.trim() == format!("-{m}")))
            .collect();
        if !off.is_empty() {
            out.push(
                Finding::new(
                    "guest.cpu-mitigations-off",
                    Severity::High,
                    &subject,
                    format!("{label} runs with {} disabled", off.join(", ")),
                )
                .detail(format!(
                    "`cpu: flags={flags}` — the guest is exposed to the side-channel families \
                     those flags mitigate, whatever the host kernel does about them."
                )),
            );
        }
    }
    if s(cfg, "kvm") == "0" {
        out.push(Finding::new(
            "guest.no-kvm",
            Severity::Info,
            &subject,
            format!("{label} runs fully emulated, without KVM"),
        ));
    }

    // UEFI without enrolled keys is UEFI without Secure Boot.
    if s(cfg, "bios") == "ovmf" {
        let efi = propstring(&s(cfg, "efidisk0"), "file");
        match prop(&efi, "pre-enrolled-keys") {
            Some("1") => {}
            _ if s(cfg, "efidisk0").is_empty() => out.push(
                Finding::new(
                    "guest.uefi-without-efidisk",
                    Severity::Low,
                    &subject,
                    format!("{label} boots UEFI with no EFI disk"),
                )
                .detail("Variables, and therefore any boot policy, are not persisted."),
            ),
            _ => out.push(
                Finding::new(
                    "guest.secure-boot-keys-missing",
                    Severity::Low,
                    &subject,
                    format!("{label} boots UEFI without enrolled Secure Boot keys"),
                )
                .detail(
                    "`pre-enrolled-keys` is not set on the EFI disk, so the firmware accepts \
                     any bootloader.",
                ),
            ),
        }
    }

    let clipboard = propstring(&s(cfg, "vga"), "type");
    if prop(&clipboard, "clipboard") == Some("vnc") {
        out.push(
            Finding::new(
                "guest.clipboard-bridged",
                Severity::Low,
                &subject,
                format!("{label} shares its clipboard with the console"),
            )
            .detail("Whatever is copied inside the guest crosses to whoever holds the console."),
        );
    }

    if !s(cfg, "cicustom").is_empty() {
        out.push(
            Finding::new(
                "guest.cloudinit-custom",
                Severity::Info,
                &subject,
                format!("{label} boots from a custom cloud-init snippet"),
            )
            .detail(format!(
                "`cicustom: {}` — whatever that snippet contains runs at first boot.",
                s(cfg, "cicustom")
            )),
        );
    }

    // A VM whose disks are all on a shared storage but that pins the host CPU
    // model cannot migrate; not security, so it stays out.
    out
}

/// Checks that read the same way on both guest types.
fn common(g: &Guest) -> Vec<Finding> {
    let mut out = Vec::new();
    let subject = g.subject();
    let label = g.label();
    let cfg = &g.config;

    let hook = s(cfg, "hookscript");
    if !hook.is_empty() {
        out.push(
            Finding::new(
                "guest.hookscript",
                Severity::Medium,
                &subject,
                format!("{label} runs a hook script on the host"),
            )
            .detail(format!(
                "`hookscript: {hook}` executes on the node at this guest's lifecycle events, as root."
            )),
        );
    }

    for (key, raw) in g.nets() {
        let p = propstring(&raw, "model");
        let bridge = prop(&p, "bridge").unwrap_or("(none)");
        if let Some(trunks) = prop(&p, "trunks") {
            out.push(
                Finding::new(
                    "guest.vlan-trunk",
                    Severity::High,
                    &subject,
                    format!("{label} receives a VLAN trunk on {key}"),
                )
                .detail(format!(
                    "`trunks={trunks}` on {bridge}: the guest chooses its own VLAN, which is the \
                     end of segmentation for those ids."
                )),
            );
        } else if prop(&p, "tag").is_none() {
            out.push(
                Finding::new(
                    "guest.untagged-nic",
                    Severity::Info,
                    &subject,
                    format!("{label} sits untagged on {bridge}"),
                )
                .detail(format!(
                    "{key} has no VLAN tag, so it shares a broadcast domain with every other \
                     untagged guest on that bridge."
                )),
            );
        }
        if prop(&p, "link_down") == Some("1") {
            out.push(Finding::new(
                "guest.link-down",
                Severity::Info,
                &subject,
                format!("{label} has {key} administratively down"),
            ));
        }
    }

    // A detached volume keeps its data and disappears from the main view.
    let unused = indexed(g, "unused");
    if !unused.is_empty() {
        out.push(
            Finding::new(
                "guest.unused-disk",
                Severity::Low,
                &subject,
                format!(
                    "{label} has {} detached disk(s) still on storage",
                    unused.len()
                ),
            )
            .detail(format!(
                "{}. Detaching a disk does not erase it: the data is still there and no longer \
                 shown next to the guest.",
                unused
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        );
    }

    // A template is not one guest, it is every clone made from it.
    if g.template {
        let mut carried = Vec::new();
        if !s(cfg, "cipassword").is_empty() {
            carried.push("a cloud-init password");
        }
        if !s(cfg, "sshkeys").is_empty() {
            carried.push("SSH keys");
        }
        if !s(cfg, "hookscript").is_empty() {
            carried.push("a hook script");
        }
        if !carried.is_empty() {
            out.push(
                Finding::new(
                    "guest.template-carries-secret",
                    Severity::Medium,
                    &subject,
                    format!("the template {label} carries {}", carried.join(" and ")),
                )
                .detail(
                    "Every clone inherits it, including the ones made by someone who never saw \
                     this configuration.",
                ),
            );
        }
    }

    if !g.template && !flag(cfg, "protection", false) && g.status == "running" {
        out.push(
            Finding::new(
                "guest.no-deletion-protection",
                Severity::Low,
                &subject,
                format!("{label} can be deleted while it runs"),
            )
            .detail("`protection: 0` — nothing stops an accidental or hostile destroy."),
        );
    }

    out
}

fn snapshots(g: &Guest, now: i64) -> Vec<Finding> {
    let mut out = Vec::new();
    for snap in &g.snapshots {
        let name = s(snap, "name");
        // `current` is the live state, not a snapshot.
        if name == "current" {
            continue;
        }
        let age_days = i(snap, "snaptime").map(|t| (now - t) / 86_400);
        let with_ram = flag(snap, "vmstate", false);

        if with_ram {
            out.push(
                Finding::new(
                    "guest.snapshot-with-memory",
                    Severity::Medium,
                    g.subject(),
                    format!("{} keeps a snapshot with RAM state ({name})", g.label()),
                )
                .detail(
                    "The memory image is written to storage in the clear: keys, sessions and \
                     passphrases that were live at the time are in that file.",
                ),
            );
        }
        if let Some(days) = age_days {
            if days > STALE_SNAPSHOT_DAYS {
                out.push(
                    Finding::new(
                        "guest.stale-snapshot",
                        Severity::Low,
                        g.subject(),
                        format!("{} has a {days}-day-old snapshot ({name})", g.label()),
                    )
                    .detail("Old snapshots grow, slow the guest down, and are not backups."),
                );
            }
        }
    }
    out
}

/// Guests holding PCI devices that sit in the same IOMMU group.
///
/// Cross-guest rather than per-guest, so it takes the whole fleet: the group is
/// the unit the hardware can isolate, and two guests inside one can reach each
/// other's memory by DMA whatever the hypervisor thinks.
pub fn iommu(guests: &[Guest], nodes: &[crate::collect::Node]) -> Vec<Finding> {
    use std::collections::BTreeMap;
    let mut by_group: BTreeMap<(String, i64), Vec<String>> = BTreeMap::new();

    for g in guests {
        for (_, raw) in indexed(g, "hostpci") {
            let p = propstring(&raw, "host");
            let Some(host) = prop(&p, "host") else {
                continue;
            };
            // A hostpci entry may list several ids, and may be a short form
            // (0000:01:00 without the function).
            for id in host.split(';') {
                let id = id.trim();
                let Some(node) = nodes.iter().find(|n| n.name == g.node) else {
                    continue;
                };
                for dev in &node.pci {
                    let dev_id = s(dev, "id");
                    if !dev_id.starts_with(id) && !id.starts_with(&dev_id) {
                        continue;
                    }
                    if let Some(group) = i(dev, "iommugroup") {
                        by_group
                            .entry((g.node.clone(), group))
                            .or_default()
                            .push(format!("{} via {dev_id}", g.label()));
                    }
                }
            }
        }
    }

    by_group
        .into_iter()
        .filter(|(_, holders)| {
            // Several entries from the same guest are fine; several guests are not.
            let distinct: std::collections::BTreeSet<&str> = holders
                .iter()
                .map(|h| h.split(" via ").next().unwrap_or(h))
                .collect();
            distinct.len() > 1
        })
        .map(|((node, group), holders)| {
            Finding::new(
                "guest.iommu-group-shared",
                Severity::High,
                format!("node/{node}"),
                format!("{} guests share IOMMU group {group}", holders.len()),
            )
            .detail(format!(
                "{}. A group is the smallest unit the hardware can isolate: a device in it can \
                 DMA into the memory of anything else in it, which is below the level any \
                 hypervisor setting reaches.",
                holders.join(", ")
            ))
        })
        .collect()
}

/// Every `prefixN` key of a config, in index order: `net0`, `mp1`, `hostpci0`.
fn indexed(g: &Guest, prefix: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Some(map) = g.config.as_object() else {
        return out;
    };
    let mut keys: Vec<&String> = map
        .keys()
        .filter(|k| {
            k.starts_with(prefix)
                && k.len() > prefix.len()
                && k[prefix.len()..].chars().all(|c| c.is_ascii_digit())
        })
        .collect();
    keys.sort();
    for k in keys {
        if let Some(v) = map[k].as_str() {
            out.push((k.clone(), v.to_string()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn guest(kind: &str, config: Value) -> Guest {
        Guest {
            node: "n1".into(),
            vmid: 100,
            kind: kind.into(),
            name: "t".into(),
            status: "running".into(),
            template: false,
            config,
            firewall: Value::Null,
            firewall_rules: vec![],
            firewall_ipsets: Default::default(),
            pending: vec![],
            agent: Default::default(),
            snapshots: vec![],
        }
    }

    #[test]
    fn a_container_without_the_flag_counts_as_privileged() {
        let g = guest("lxc", json!({ "hostname": "c1" }));
        let out = container(&g);
        assert!(out.iter().any(|f| f.id == "guest.privileged-container"));
    }

    #[test]
    fn privileged_plus_nesting_is_the_only_critical_here() {
        let g = guest("lxc", json!({ "features": "nesting=1" }));
        let out = container(&g);
        let f = out
            .iter()
            .find(|f| f.id == "guest.privileged-nesting")
            .unwrap();
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn nesting_on_an_unprivileged_container_is_only_noted() {
        let g = guest("lxc", json!({ "unprivileged": 1, "features": "nesting=1" }));
        let out = container(&g);
        assert!(out.iter().all(|f| f.severity != Severity::Critical));
        assert!(out.iter().any(|f| f.id == "guest.container-nesting"));
    }

    #[test]
    fn a_bind_mount_is_told_apart_from_a_storage_volume() {
        let g = guest(
            "lxc",
            json!({
                "unprivileged": 1,
                "mp0": "local-lvm:vm-100-disk-1,mp=/data,size=8G",
                "mp1": "/srv/host-share,mp=/mnt/share"
            }),
        );
        let out = container(&g);
        let binds: Vec<&Finding> = out.iter().filter(|f| f.id == "guest.bind-mount").collect();
        assert_eq!(binds.len(), 1);
        assert!(binds[0].title.contains("/srv/host-share"));
    }

    #[test]
    fn raw_qemu_arguments_are_reported_with_their_value() {
        let g = guest("qemu", json!({ "args": "-chardev socket,id=x" }));
        let out = vm(&g);
        let f = out.iter().find(|f| f.id == "guest.raw-args").unwrap();
        assert!(f.detail.contains("-chardev"));
    }

    #[test]
    fn a_trunk_outranks_a_missing_tag() {
        let trunk = guest(
            "qemu",
            json!({ "net0": "virtio=AA,bridge=vmbr0,trunks=10;20" }),
        );
        let flat = guest("qemu", json!({ "net0": "virtio=AA,bridge=vmbr0" }));
        assert_eq!(
            common(&trunk)
                .iter()
                .find(|f| f.id == "guest.vlan-trunk")
                .unwrap()
                .severity,
            Severity::High
        );
        assert_eq!(
            common(&flat)
                .iter()
                .find(|f| f.id == "guest.untagged-nic")
                .unwrap()
                .severity,
            Severity::Info
        );
    }

    #[test]
    fn a_memory_snapshot_is_a_secret_on_disk() {
        let mut g = guest("qemu", json!({}));
        g.snapshots = vec![json!({ "name": "before-upgrade", "vmstate": 1, "snaptime": 1 })];
        let out = snapshots(&g, 1_000_000);
        assert!(out.iter().any(|f| f.id == "guest.snapshot-with-memory"));
    }

    #[test]
    fn a_staged_change_makes_every_other_finding_about_a_guest_conditional() {
        let mut g = guest("qemu", json!({}));
        g.pending = vec!["net0".into(), "memory".into()];
        let out = state(&g);
        let f = out
            .iter()
            .find(|f| f.id == "guest.pending-changes")
            .unwrap();
        assert!(f.detail.contains("net0, memory"));
        assert!(f.detail.contains("not what is running"));
    }

    #[test]
    fn an_agent_that_is_declared_and_silent_is_worse_than_no_agent() {
        let mut g = guest("qemu", json!({ "agent": "enabled=1" }));
        g.agent = crate::collect::Agent {
            configured: true,
            alive: false,
            ..Default::default()
        };
        assert!(state(&g).iter().any(|f| f.id == "guest.agent-not-running"));

        // Stopped: nothing to freeze, nothing to report.
        g.status = "stopped".into();
        assert!(!state(&g).iter().any(|f| f.id == "guest.agent-not-running"));
    }

    #[test]
    fn a_lock_left_behind_blocks_the_next_backup() {
        let g = guest("qemu", json!({ "lock": "backup" }));
        assert!(state(&g).iter().any(|f| f.id == "guest.locked"));
    }

    #[test]
    fn a_console_that_opens_a_shell_asks_for_nothing() {
        let g = guest("lxc", json!({ "unprivileged": 1, "cmode": "shell" }));
        assert!(container(&g)
            .iter()
            .any(|f| f.id == "guest.console-without-login"));
        let g = guest("lxc", json!({ "unprivileged": 1 }));
        assert!(!container(&g)
            .iter()
            .any(|f| f.id == "guest.console-without-login"));
    }

    #[test]
    fn a_custom_idmap_undoes_what_unprivileged_means() {
        let g = guest(
            "lxc",
            json!({ "unprivileged": 1, "rootfs": "local-lvm:vm-100-disk-0,idmap=u:0:100000:65536" }),
        );
        assert!(container(&g).iter().any(|f| f.id == "guest.custom-idmap"));
    }

    #[test]
    fn a_writable_bind_mount_without_nosuid_is_its_own_finding() {
        let g = guest(
            "lxc",
            json!({ "unprivileged": 1, "mp0": "/srv/data,mp=/data" }),
        );
        let out = container(&g);
        assert!(out.iter().any(|f| f.id == "guest.bind-mount"));
        let f = out
            .iter()
            .find(|f| f.id == "guest.bind-mount-options")
            .unwrap();
        assert!(f.title.contains("nosuid"));

        let g = guest(
            "lxc",
            json!({ "unprivileged": 1, "mp0": "/srv/data,mp=/data,mountoptions=nosuid;nodev;noexec" }),
        );
        assert!(!container(&g)
            .iter()
            .any(|f| f.id == "guest.bind-mount-options"));
    }

    #[test]
    fn a_negated_mitigation_flag_is_high_and_a_plain_cpu_type_is_nothing() {
        let g = guest("qemu", json!({ "cpu": "host,flags=-spec-ctrl;+pdpe1gb" }));
        let f = vm(&g)
            .iter()
            .find(|f| f.id == "guest.cpu-mitigations-off")
            .cloned()
            .unwrap();
        assert_eq!(f.severity, Severity::High);

        let g = guest("qemu", json!({ "cpu": "host" }));
        assert!(!vm(&g).iter().any(|f| f.id == "guest.cpu-mitigations-off"));
    }

    #[test]
    fn uefi_without_enrolled_keys_is_uefi_without_secure_boot() {
        let g = guest(
            "qemu",
            json!({ "bios": "ovmf", "efidisk0": "local-lvm:vm-100-disk-1,efitype=4m,pre-enrolled-keys=0,size=528K" }),
        );
        assert!(vm(&g)
            .iter()
            .any(|f| f.id == "guest.secure-boot-keys-missing"));

        let g = guest(
            "qemu",
            json!({ "bios": "ovmf", "efidisk0": "local-lvm:vm-100-disk-1,pre-enrolled-keys=1" }),
        );
        assert!(!vm(&g).iter().any(|f| f.id.starts_with("guest.secure-boot")));

        // SeaBIOS has no Secure Boot to be missing.
        let g = guest("qemu", json!({ "bios": "seabios" }));
        assert!(!vm(&g).iter().any(|f| f.id.contains("secure-boot")));
    }

    #[test]
    fn a_detached_disk_still_holds_its_data() {
        let g = guest(
            "qemu",
            json!({ "unused0": "local-lvm:vm-100-disk-3", "unused1": "vmstore:vm-100-disk-9" }),
        );
        let f = common(&g)
            .iter()
            .find(|f| f.id == "guest.unused-disk")
            .cloned()
            .unwrap();
        assert!(f.title.contains("2 detached"));
    }

    #[test]
    fn a_template_is_graded_as_every_clone_it_will_produce() {
        let mut g = guest(
            "qemu",
            json!({ "cipassword": "x", "sshkeys": "ssh-ed25519 AAAA" }),
        );
        g.template = true;
        let f = common(&g)
            .iter()
            .find(|f| f.id == "guest.template-carries-secret")
            .cloned()
            .unwrap();
        assert!(f.title.contains("cloud-init password"));
        assert!(f.title.contains("SSH keys"));
    }

    #[test]
    fn two_guests_in_one_iommu_group_is_a_hardware_problem_not_a_config_one() {
        let mut a = guest("qemu", json!({ "hostpci0": "0000:01:00.0" }));
        a.vmid = 100;
        a.name = "a".into();
        let mut b = guest("qemu", json!({ "hostpci0": "0000:01:00.1" }));
        b.vmid = 101;
        b.name = "b".into();

        let node = crate::collect::Node {
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
            pci: vec![
                json!({ "id": "0000:01:00.0", "iommugroup": 14 }),
                json!({ "id": "0000:01:00.1", "iommugroup": 14 }),
            ],
            thin_pools: vec![],
            zfs_pools: vec![],
            hosts: Value::Null,
            firewall: Value::Null,
            firewall_rules: vec![],
            updates: None,
            packages: vec![],
        };
        let out = iommu(&[a.clone(), b], std::slice::from_ref(&node));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::High);

        // One guest holding both functions is not sharing with anybody.
        let out = iommu(&[a], std::slice::from_ref(&node));
        assert!(out.is_empty());
    }
}
