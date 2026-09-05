# Passive security

What a read-only Proxmox token supports in defensive work, without sending a
packet at anything.

Passive here means strictly: no scanning, no probing, no configuration writes.
Everything starts from what the cluster has already recorded about itself. The
hypervisor is the sensor; mlab-proxmox reads it.

## The capabilities

**direct** means the data is the answer, **derived** means it has to be joined
or computed, **gated** means it needs a privilege beyond the auditor role.

| Capability | What it detects | Source | Status |
| --- | --- | --- | --- |
| Guest inventory | every VM and container with its live state, in one call | `/cluster/resources` | direct |
| Container isolation | privileged containers, nesting, keyctl, mount, bind mounts, device passthrough | lxc config | direct |
| VM escape surface | raw `args`, PCI and USB passthrough, virtiofs, shared memory, hook scripts | qemu config | direct |
| Cloud-init secrets | passwords in guest config, custom snippets that run at first boot, and templates that hand them to every clone | qemu config | direct |
| Guest inventory | OS, hostname, interfaces and open sessions, without a packet on the guest network | `agent/get-osinfo`, `network-get-interfaces`, `get-users` | direct |
| Agent that lies by absence | `agent: enabled=1` and nothing answering, so backups skip the filesystem freeze | `agent/info` | direct |
| Running versus stored config | keys staged for the next start, which make every other guest finding conditional | `{guest}/pending` | direct |
| Hardware isolation | guests sharing an IOMMU group, below the level any hypervisor setting reaches | guest config + `/nodes/{n}/hardware/pci` | derived |
| CPU exposure | side-channel mitigations turned off per guest with a negated flag | qemu config | direct |
| Segmentation | guests sharing a bridge and VLAN, trunks handed to a guest, untagged NICs | guest config + node network | derived |
| Firewall reality | the four switches, and whether a rule applies to anything | firewall options at four levels | derived |
| Rules inside a group | the ACCEPTs a rule of type `group` hides behind a reference | `/cluster/firewall/groups/{group}` | direct |
| Who may reach the management ports | the members of the `management` IP set, and whether one of them is a default route | `/cluster/firewall/ipset/{name}` | direct |
| Kernel-level bypass | connection tracking helpers, invalid packets accepted, ebtables off | `/nodes/{n}/firewall/options` | direct |
| Firewall drops | what the host firewall is refusing, per rule | `/nodes/{n}/firewall/log` | direct (needs `Sys.Syslog`) |
| Ignored protection | forward rules on a node running the iptables engine | node firewall options | derived |
| Access sprawl | who holds an administrative role, where, and how far it propagates | `/access/acl` + `/access/roles` | derived |
| Second factor coverage | accounts with no factor, with only disabled ones, or with recovery keys alone; realms that do not enforce one | `/access/users`, `/access/tfa`, `/access/domains` | derived |
| Second factor lockout | an account failing its second factor right now | `/access/tfa` | direct |
| ACL hygiene | grants naming a principal or role that no longer exists, deeper grants that replace an inherited one, `NoAccess` carve-outs, groups with grants and no member | `/access/acl` joined to users, groups and roles | derived |
| Directory drift | a sync job that lets a departed user keep their grants, or that never runs | `/cluster/jobs/realm-sync` | direct |
| Token hygiene | privilege separation off, no expiry | `/access/users/{u}/token` | gated (`User.Modify`) |
| Backup coverage | guests no job covers, computed by the API | `/cluster/backup-info/not-backed-up` | direct |
| Backup reality | jobs disabled, thin retention, local-only targets, failed tasks | `/cluster/backup` + task log | derived |
| Backups that exist | the files on the storage, per guest, with their age and PBS verification verdict — a job covers on paper, this is what landed | `/nodes/{n}/storage/{s}/content` | direct |
| A schedule that never fires | a calendar expression the scheduler cannot place, or a next run in the past | `/cluster/backup` | direct |
| Room to keep working | storages at 90%, LVM thin pools at 95% (metadata fills first), ZFS pools not `ONLINE` | `/nodes/{n}/storage`, `/disks/lvmthin`, `/disks/zfs` | direct |
| Replication reality | jobs with failures behind them | `/cluster/replication` | direct |
| Patch posture | repositories, subscription, version skew across nodes | `/nodes/{n}/apt/repositories`, `/subscription` | direct |
| Pending updates | packages waiting, security ones named | `/nodes/{n}/apt/update` | gated (`Sys.Modify`) |
| Certificate posture | self-signed, expiring, weak keys, SANs | `/nodes/{n}/certificates/info` | direct |
| Host health | services not running, clock drift, SMART failures | `/nodes/{n}/services`, `/time`, `/disks/list` | direct |
| Cluster integrity | quorum, membership **against the QDevice that settles it**, corosync links, insecure migration, HA resources in error | `/cluster/status`, `/config/totem`, `/config/qdevice`, `/ha/status/current` | direct |
| A reboot owed | a kernel installed and not running | `/nodes/{n}/apt/versions` + `/status` | derived |
| The host under the cluster | a full root filesystem, a name resolving to loopback, no time service running | `/nodes/{n}/status`, `/hosts`, `/services` | direct |
| Egress | metrics servers, webhook targets, a proxy URL with credentials | `/cluster/metrics/server`, `/notifications/*`, `/options` | direct |
| Blast radius | what one guest reaches at layer 2, and whether the host is on that segment | guest config + node network + firewall | derived |
| Forensics | who did what, and whether it worked | `/nodes/{n}/tasks` | direct |
| Authentication failures | brute force against 8006, grouped by user and source | `/cluster/log` | direct |
| Root shells on a host | console sessions on the hypervisor itself | `/cluster/tasks` | direct |
| Shadow infrastructure | guests, users, tokens and grants that appeared since the last record | snapshot diff | derived |

## What the API cannot answer

Measured, not assumed. Three questions a reader will ask that no route can settle,
so no check pretends to:

| Question | Why not |
| --- | --- |
| What is running inside a guest? | Only the guest agent can say, and it is the guest describing itself. Patch level, services and local accounts are reported by the machine under audit — an inventory, never a verification. Without an agent, nothing at all. |
| Was that detached disk erased? | Volume contents are not readable through the API, so an `unused` disk is reported as present and never as clean. |
| What is the firewall actually enforcing right now? | No route exposes the compiled ruleset — neither `iptables-save` nor the nftables set. Everything here audits the configuration; a drift between it and what the kernel loaded is invisible. |
| When did this user last log in? | There is no last-login field anywhere in the API. The task log records sessions and is finite, so it bounds the answer rather than giving it. |
| Is this password old, or weak? | Never exposed, for any realm. |
| Has this token ever been used? | Tokens carry a creation comment and an expiry, and no last-used timestamp. An abandoned token is indistinguishable from a busy one. |

## The two gaps, and why they stay open

Two reads need a privilege that is not read-only, and mlab-proxmox refuses to
require either by default:

- **Pending updates** need `Sys.Modify`, which also rewrites the host's network
  configuration.
- **Other users' tokens** need `User.Modify`, which also administers users.

Both are reported as `unreadable` findings rather than skipped, so a report
never implies a check passed when it never ran. [Token](Token) shows how to
grant them deliberately.

## Detection is differential

There is no event stream in the Proxmox API. No alarm endpoint, no IDS feed,
nothing that pushes. The websocket routes are console and migration tunnels;
the web interface polls.

So detection here does not read an alert — it compares two dated records and
qualifies the difference. That is slower than a signature and considerably
harder to evade: an attacker can avoid triggering a rule, but can hardly avoid
existing in the inventory.

This is why [`snapshot`](Snapshot) comes before everything else in the
[roadmap](Roadmap), and why [`shadow`](Shadow) is the command worth putting on
a schedule.

## What this tool will not do

- **Probe.** No port scan, no service fingerprint, no packet at any target. The
  port list in [`footprint`](Footprint) comes from the documentation and says so.
- **Guess at rule ordering.** Which firewall rule shadows which depends on the
  full match semantics of the engine in use; a wrong answer is worse than none.
- **Reach inside a guest.** The QEMU guest agent can report an OS, interfaces
  and logged-in users, and reading files or running commands through it needs
  privileges this tool does not ask for.
- **Write.** Every wrapped command issues GETs. [`api`](Api) will send whatever
  you tell it to, and your token's privileges are what stop it.
