# Checks

Every graded observation this CLI can make, with the identifier it carries in
`-o json`. Nothing here performs I/O: the checks are pure functions over what
[`collect`](Snapshot) already fetched, which is what makes each one testable
against a literal.

## Severities

| Level | Means |
| --- | --- |
| `critical` | Exploitable now, or the cluster is already not working. |
| `high` | A defence that is off, missing, or applies to nothing. |
| `medium` | A real weakening, or a defence that only half applies. |
| `low` | Worth knowing, not worth waking up for. |
| `info` | A fact about the cluster that a reader needs to interpret the rest. |
| `unreadable` | **Not a grade.** The check could not run because the token was refused the data. |

That last one is the important one. A check that reports nothing because it was
refused is not a check that passed, and it is never hidden — `--min` filters
every level except `unreadable`.

## Cluster

| id | Severity | What it catches |
| --- | --- | --- |
| `cluster.no-quorum` | critical | pmxcfs is read-only; nothing starts, nothing changes. |
| `cluster.ha-no-quorum` | critical | The HA manager itself reports quorum lost. |
| `cluster.ha-resource-error` | high | HA gave up on a resource, or a node is being fenced. |
| `cluster.node-offline` | high | A member is not answering. |
| `cluster.even-membership` | medium | An even node count **and no QDevice**: a clean split leaves neither half quorate. |
| `cluster.single-corosync-link` | medium | One network interruption costs quorum. |
| `cluster.corosync-unencrypted` | high | Cluster traffic can be read and forged on that segment. |
| `cluster.insecure-migration` | high | Guest memory crosses the network in the clear. |
| `cluster.proxy-credentials` | high | `http_proxy` in datacenter.cfg carries a password in clear text. |
| `cluster.replication-disabled` | medium | A failover would start from stale data. |
| `cluster.ha-resource-disabled` | low | Registered with HA, and HA will not restart it. |
| `cluster.ha-shutdown-freeze` | info | HA resources freeze on shutdown rather than migrating. |
| `cluster.custom-mac-prefix` | info | Guest MACs use a prefix other than the assigned `BC:24:11`. |
| `cluster.standalone` | info | Not a cluster; the checks above do not apply. |

## Access

| id | Severity | What it catches |
| --- | --- | --- |
| `access.privileged-grant` | high / medium | An ACL entry handing out Administrator, or a role carrying a privilege that changes the system. High at `/`. |
| `access.custom-role-privileged` | medium | A hand-made role that quietly includes `Sys.Modify`, `Permissions.Modify`, `Realm.Allocate`, `Sys.PowerMgmt`, `Sys.Console` or `User.Modify`. |
| `access.no-tfa` | high / medium | An enabled account with no second factor, in a realm that does not enforce one. High for `root@pam`. |
| `access.tfa-all-disabled` | high / medium | Factors are registered and every one of them is disabled: the user list reads as protected, the login is a password. |
| `access.tfa-recovery-only` | high / medium | The only factor is recovery keys — single-use, printed, and not a daily second factor. |
| `access.tfa-locked` | medium | The account is locked out of its second factor right now: either a struggling owner, or somebody who already has the password. |
| `access.token-full-privileges` | medium | Privilege separation off: the token carries everything its user has. |
| `access.token-no-expiry` | low | Abandoned automation keeps working. |
| `access.token-expired` | info | Refused at authentication, still listed. |
| `access.user-expired` | low | The account is past its expiry date and still enabled. |
| `access.user-disabled` | info | Disabled, but its ACL entries and tokens survive. |
| `access.realm-no-tfa` | low | An LDAP or AD realm that does not enforce a factor. |
| `access.realm-sync-keeps-acl` | medium | A sync job whose `remove-vanished` omits `acl`: a user deleted from the directory keeps their grants here. |
| `access.realm-sync-disabled` | low | The directory and the cluster drift apart from here on. |
| `access.realm-sync-never-ran` | low | Configured, never executed. |
| `access.acl-orphan` | medium | A grant naming a user, group or token that does not exist — inert until something is created with that name. |
| `access.acl-unknown-role` | medium | A grant referencing a role that does not exist. |
| `access.acl-override` | low | A deeper grant **replaces** an inherited one rather than adding to it, so the deeper path may grant less than the one above. |
| `access.empty-group-grant` | low | A group with grants and no member: whoever is added next inherits them. |
| `access.acl-noaccess` | info | A `NoAccess` deny, listed next to what it carves into. |
| `access.realm-list-public` | info | True on every Proxmox host; said once rather than never. |
| `access.tokens-unreadable` | unreadable | Listing other users' tokens needs `User.Modify`. |

## Firewall

| id | Severity | What it catches |
| --- | --- | --- |
| `firewall.cluster-disabled` | high | The datacenter switch is off, so no rule at any level applies. |
| `firewall.policy-accept` | high | The default inbound or forward policy is ACCEPT. |
| `firewall.forward-rules-ignored` | high | Forward rules exist and the node runs the iptables engine, which ignores them. |
| `firewall.node-disabled` | high | A node overrides the datacenter and filters nothing. |
| `firewall.guest-switch-off` | high | A NIC is marked as filtered and the guest's own switch is off. |
| `firewall.nic-unfiltered` | high | The guest firewall is on and no NIC carries `firewall=1`: no packet is inspected. |
| `firewall.ipset-open` | high / medium | An IP set containing `0.0.0.0/0`. High for `management`, whose members may reach 8006, 22 and 3128. |
| `firewall.guest-unprotected` | medium | The guest has no firewall of its own. |
| `firewall.macfilter-off` | medium | The guest may spoof its MAC. |
| `firewall.ipfilter-off` | medium | The guest may send from any IP address; MAC filtering alone does not stop it. |
| `firewall.conntrack-helpers` | medium | Kernel helpers open pinholes from what they parse in the traffic itself. |
| `firewall.conntrack-invalid` | medium | Packets that fail connection tracking are allowed through. |
| `firewall.no-logging` | medium | The firewall is on and every direction is at `nolog`: it cannot answer what it dropped. |
| `firewall.empty-group` | medium / info | A security group with no rule. Medium once a rule invokes it. |
| `firewall.radv-allowed` | medium | The guest may advertise itself as an IPv6 router. |
| `firewall.accept-from-anywhere` | medium | An ACCEPT rule with no source restriction. |
| `firewall.accept-unlogged` | low | An ACCEPT rule that logs nothing. |
| `firewall.duplicate-rule` | low | Two enabled rules matching exactly the same traffic. |
| `firewall.ebtables-off` | low | No filtering at the MAC layer, where guest anti-spoofing lives. |
| `firewall.log-ratelimit-off` | low | A packet loop writes as fast as the disk accepts it. |
| `firewall.no-management-ipset` | low | Nothing restricts who may reach 8006, 22 and 3128. |
| `firewall.tcpflags-off` | low | Illegal TCP flag combinations are not filtered. |
| `firewall.guest-policy-accept` | medium | A guest whose own inbound policy is ACCEPT. |
| `firewall.rules-disabled` | info | Disabled rules read as protection in a review. |
| `firewall.unused-object` | info | An alias or IP set defined and referenced by no rule. |

Rule hygiene runs at every level that carries rules, **security groups
included** — a rule of type `group` is a reference, and the ACCEPTs live in the
group. A finding inside one is attributed to `group/<name>` rather than to the
rule that invoked it.

Two things are deliberately absent. **Rule ordering** is never analysed: which
rule shadows which depends on the full match semantics of the engine in use,
and a wrong answer is worse than none — `firewall.duplicate-rule` reports
identical rules only. And the **compiled ruleset** is unreachable: no API route
exposes `iptables-save` or the nftables set, so everything here audits the
configuration, never what the kernel currently applies.

## Guests

| id | Severity | What it catches |
| --- | --- | --- |
| `guest.privileged-nesting` | critical | Privileged **and** nesting: the documented escape path. |
| `guest.privileged-container` | high | root in the container is root on the host. |
| `guest.container-mount` | high | The container may mount a real filesystem type itself. |
| `guest.bind-mount` | high / medium | A host directory mapped into the container. Medium when read-only. |
| `guest.raw-args` | high | `args:` is appended to the kvm command line, invisible to every other setting. |
| `guest.cpu-mitigations-off` | high | A negated `spec-ctrl`, `md-clear`, `ibpb` or `ssbd` flag: the guest is exposed to those side channels whatever the host kernel does. |
| `guest.iommu-group-shared` | high | Two guests hold devices in one IOMMU group, the smallest unit the hardware can isolate. |
| `guest.vlan-trunk` | high | The guest chooses its own VLAN. |
| `guest.pci-passthrough` | medium | A DMA-capable device; isolation rests on the IOMMU group. |
| `guest.virtiofs-share` | medium | A host filesystem exposed to a VM. |
| `guest.shared-memory` | medium | `ivshmem`: a channel no firewall sees. |
| `guest.hookscript` | medium | Code that runs on the node as root at lifecycle events. |
| `guest.device-passthrough` | medium | A host device node inside a container. |
| `guest.container-feature` | medium / low | `keyctl`, `mknod`, `force_rw_sys`, `fuse`. |
| `guest.cloudinit-password` | medium | A reusable secret in the guest config. |
| `guest.template-carries-secret` | medium | A template with a cloud-init password, SSH keys or a hook script: every clone inherits it. |
| `guest.pending-changes` | medium | Settings staged for the next start, so the rest of this report describes a guest that is not running yet. |
| `guest.agent-not-running` | medium | `agent: enabled=1` and nothing answers: snapshot backups are taken without the filesystem freeze the config implies. |
| `guest.locked` | medium | A lock left by an interrupted backup, migration or clone blocks every later operation. |
| `guest.console-without-login` | medium | `cmode: shell` — the console opens a shell instead of a login. |
| `guest.custom-idmap` | medium | A uid remapping override, which is what unprivileged containment rests on. |
| `guest.bind-mount-options` | medium | A writable host path mounted without `nosuid`, `nodev` or `noexec`. |
| `guest.snapshot-with-memory` | medium | A RAM image on storage: whatever was live is in that file. |
| `guest.usb-passthrough` | low | A physical port attached to the guest. |
| `guest.container-nesting` | low | Expected for Docker in LXC; noted, not condemned. |
| `guest.stale-snapshot` | low | Older than 90 days. Snapshots are not backups. |
| `guest.unused-disk` | low | A detached volume still on storage: detaching does not erase. |
| `guest.secure-boot-keys-missing` | low | UEFI with no enrolled keys, so the firmware accepts any bootloader. |
| `guest.uefi-without-efidisk` | low | UEFI with no EFI disk: no variable, no boot policy persisted. |
| `guest.clipboard-bridged` | low | `vga: clipboard=vnc` carries what is copied inside the guest to whoever holds the console. |
| `guest.no-deletion-protection` | low | Nothing stops a destroy. |
| `guest.untagged-nic` | info | Shares a broadcast domain with every other untagged guest. |
| `guest.cloudinit-custom` | info | A snippet that runs at first boot. |
| `guest.link-down` | info | Administratively down. |
| `guest.no-kvm` | info | Fully emulated. |
| `guest.logged-in-users` | info | Sessions open, as reported by the agent — the guest describing itself. |

Two of these deserve a note. `guest.pending-changes` is not a hardening
finding, it is a caveat on all the others: every check here reads the stored
configuration, and a staged key means the running guest is enforcing something
else. And the agent findings are an **inventory**, never a verification — a
compromised guest answers whatever it likes.

## Backup and storage

| id | Severity | What it catches |
| --- | --- | --- |
| `backup.no-jobs` | high | Nothing is scheduled at all. |
| `backup.uncovered-guests` | high | Guests no job covers, from `/cluster/backup-info/not-backed-up`. |
| `backup.recent-failure` | high | A vzdump task that did not end in OK. |
| `backup.no-file` | high | A guest a job covers on paper, with no backup file on any readable storage. |
| `backup.stale-file` | high | No backup newer than 14 days for a covered guest. |
| `backup.verification-failed` | high | PBS verified a snapshot and it did not pass. |
| `backup.schedule-never-fires` | high | The scheduler cannot place the job's calendar expression: configured and dormant. |
| `backup.next-run-past` | high | The next run is in the past, so the timer is not firing. |
| `backup.replication-failing` | high | A replication job with failures behind it: a failover would start from stale data. |
| `storage.thin-pool-full` | critical | An LVM thin pool at 95%. It does not return an error, it corrupts — and metadata fills before data. |
| `storage.zfs-degraded` | high | A pool that is not `ONLINE`: redundancy is reduced or gone. |
| `storage.almost-full` | high / medium | A storage at 90%. High when it accepts backups, because the next one fails rather than rotating. |
| `backup.never-ran` | high | Jobs exist and no backup task appears in the visible history. |
| `backup.stale` | high | The last backup task ran more than two weeks ago. |
| `storage.no-backup-target` | high | No storage lists `backup` in its content types. |
| `backup.job-disabled` | medium | In the list, covering nothing. |
| `backup.local-target` | medium | The backup lives on the node it protects. |
| `backup.thin-retention` | medium | One copy: corruption that survives a cycle overwrites it. |
| `storage.pbs-unpinned` | medium | A backup server used without a pinned fingerprint. |
| `storage.pbs-unencrypted` | medium | No encryption key: the backup server reads guest disks in the clear. |
| `backup.snapshots-only` | medium | Snapshots and no backup. A snapshot lives on the storage it protects and dies with it. |
| `backup.no-notification` | low | Nobody is told when it fails. |
| `storage.disabled` | info | Configured, disabled, and still referenced by whatever used it. |
| `storage.network-filesystem` | info | An NFS or CIFS share: its access control is the server's, not Proxmox's. |

## Patch

| id | Severity | What it catches |
| --- | --- | --- |
| `patch.enterprise-without-subscription` | high | Every `apt update` fails 401; no security update ever lands. |
| `patch.no-proxmox-repository` | high | Nothing on this node will ever receive a Proxmox update. |
| `patch.updates-pending` | high / low | High when any of them is a security update. |
| `patch.reboot-required` | high | A newer kernel is installed than the one running: its fixes take effect at the next boot and not before. Read from `apt/versions`, which needs no privilege beyond the audit role. |
| `patch.test-repository` | medium | Test packages on a machine somebody depends on. |
| `patch.repository-error` | medium | A sources file that does not parse. |
| `patch.third-party-repository` | low | Its maintainer can install anything at the next upgrade. |
| `patch.version-skew` | medium | Cluster nodes on different builds. |
| `patch.no-subscription` | info | The subscription status the node reports. |
| `patch.kernel` | info | The running kernel and the boot mode. |
| `patch.subscription-due` | info | When the subscription runs out. |
| `patch.updates-unreadable` | unreadable | Needs `Sys.Modify`. |

## Exposure

| id | Severity | What it catches |
| --- | --- | --- |
| `exposure.certificate-expired` | high | Already past `notafter`. |
| `exposure.certificate-weak-key` | high | RSA below 2048 bits. |
| `exposure.service-not-running` | high | pveproxy, pvestatd, corosync, or pve-firewall while the firewall is meant to be on. |
| `exposure.disk-health` | high | SMART says something other than PASSED. |
| `exposure.rootfs-full` | critical / high | pmxcfs keeps the cluster configuration on this filesystem. Critical at 95%. |
| `exposure.name-loopback` | high | The node's own name resolves to 127.x on itself, which hands every other member an address meaning "themselves". |
| `exposure.name-unresolved` | medium | The node does not appear in its own `/etc/hosts`. |
| `exposure.no-time-sync` | medium | A time service is installed and stopped. Certificates, tickets, corosync and log correlation all rest on the clock. |
| `exposure.certificate-san-mismatch` | medium | The served certificate names neither this node nor a wildcard covering it. |
| `exposure.certificate-expiring` | medium | Inside 30 days. |
| `exposure.clock-drift` | medium | More than 60s from this machine: certificates, tickets and log correlation all depend on it. |
| `exposure.public-address` | medium | A node interface with a routable address. |
| `exposure.certificate-self-signed` | low | Trains everyone to click through warnings. |
| `exposure.metrics-export` | info | Metrics shipped to an external collector, continuously. |
| `exposure.notification-target` | info | Task output and failure text sent to an external webhook or Gotify endpoint. |

## Detection

Read from the cluster log and the task log. Both rotate, so every count here
**bounds** what happened rather than measuring it, and each finding says so.

| id | Severity | What it catches |
| --- | --- | --- |
| `detection.auth-failures` | high / medium | Failed authentications, grouped by user and source address. High once one source passes five, which is where a typo stops being a plausible explanation. |
| `detection.failed-tasks` | low | Tasks that ended in an error, excluding backups, which the backup checks own. |
| `detection.host-console` | info | Root shells opened on a node in the last 7 days — outside every guest-level control, and the one action in that log worth recognising. |

## Blast radius

| id | Severity | What it catches |
| --- | --- | --- |
| `blast.unfiltered-segment` | high | Every guest on the bridge is one ARP away, with no filter anywhere. |
| `blast.unfiltered-neighbours` | medium | Neighbours whose own switch is off. |
| `blast.host-on-segment` | medium | The hypervisor answers on the guest's own segment. |
| `blast.pci-path` | medium | Reach that is not the network. |
| `blast.isolated` | info | Nothing shares this bridge and VLAN. |
