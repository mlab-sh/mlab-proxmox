# Roadmap

The order is deliberate: each step is usable on its own, and each one makes the
next cheaper.

## Done

**The core CLI.** Profiles with precedence, an HTTP handler over the one
Proxmox surface, typed API errors with the parameter complaints unpacked, a
retry for the transport failure that costs a whole section of a collection, the
human render and the JSON passthrough, and progress that never pollutes a pipe.

**The credential, understood.** [`whoami`](Whoami) asks the cluster what this
token may actually do, [`login`](Login) reports it at setup time, and every
graded command distinguishes "clean" from "refused". [Token](Token) documents
the four commands that create the role this tool wants.

**Inventory.** [`nodes`](Nodes), [`guests`](Guests) and [`storage`](Storage)
over `/cluster/resources` and the per-object configuration.

**Access control.** [`access`](Access) reads users, tokens, roles, the full ACL
tree and the realms, and grades administrative sprawl, missing second factors
and token hygiene.

**The firewall, at four levels.** [`firewall`](Firewall) reports the switches
that have to agree, and names the two ways a rule ends up applying to nothing.

**Guest hardening.** [`guests check`](Guests) reads every configuration and
reports privileged containers, escape features, bind mounts, raw QEMU
arguments, passthrough, hook scripts and cloud-init secrets.

**Backup.** [`backup`](Backup) joins the API's own uncovered-guest list to job
health, retention, target locality and what the task log says actually ran.

**Patch state.** [`patch`](Patch) reads repositories and subscription, and is
honest about the update list it is not allowed to see.

**Exposure.** [`footprint`](Footprint) reports addresses, certificates, the
pre-authentication realm list and everything that leaves the cluster on its own.

**Blast radius.** [`blast`](Blast) computes layer-2 reach from bridge and VLAN,
and states plainly where the model stops.

**Forensics.** [`tasks`](Tasks) reads the only history the API keeps, with
server-side filters and a `--follow` that is honest about being a poller.

**One graded report.** [`audit`](Audit) runs every check in one pass, with
`--min` and a `--fail-on` exit code, over a collection whose refusals are part
of the output.

**The dated record.** [`snapshot`](Snapshot), [`diff`](Diff) and
[`shadow`](Shadow): secrets redacted on write, live counters excluded from the
comparison, and a refusal to compare across a blind spot.

## Next

- **Realm configuration.** `GET /access/domains/{realm}` is reachable with the
  audit role and carries the settings that matter for a directory: `secure=0`
  (the bind DN and its password cross the network in clear), `verify=0` (the
  directory's certificate is not checked), `default` (which realm the login box
  preselects), and `autocreate=1` on an OpenID realm — which hands a Proxmox
  account to anyone the identity provider authenticates. The index route this
  CLI already reads carries none of it.

  Not built yet for one reason: every cluster tested so far has only `pam` and
  `pve` realms, so the field shapes for LDAP, AD and OpenID cannot be verified
  against a live host. Writing checks against a schema alone is how you ship a
  rule that fires on the wrong field.

- **The VNet firewall.** SDN VNets carry a fifth filtering level
  (`/cluster/sdn/vnets/{vnet}/firewall/options` and `/rules`), which this CLI
  does not collect at all. Not built for the same reason as the realms: no
  cluster tested so far runs SDN, so the rules would be written against a
  schema and nothing else.

- **Bridge VLAN modelling.** `bridge_vlan_aware` is readable and currently
  unused. The obvious check — "this bridge is not VLAN aware" — is not a
  finding: Proxmox falls back to the traditional per-VLAN interface model,
  which isolates just as well. Saying something useful here needs a host
  running that model to see what actually distinguishes a segmented setup from
  a flat one.

- **A policy for the settings that are only risks in context.** Memory
  dedup (`allow-ksm`, on by default), a mounted ISO, a serial socket and USB
  hotplug are all normal on a single-tenant lab and all worth flagging on a
  shared host. The API cannot tell the two apart, so these need something the
  operator declares — a tag convention, or a flag on the command — before they
  become findings rather than noise.

- **Secure Boot and vTPM as a policy rather than a fact.** Both are read and
  reported today; deciding that their *absence* is a finding needs to know
  what the fleet is meant to be, which no route says.

- **The journal, beyond the cluster log.** Authentication is covered by
  [`logins`](Logins) over `/cluster/log`. The journal adds what happens below
  Proxmox — sshd, sudo, the kernel — and on 9.1 it accepts only `lastentries`,
  `since`, `until` and cursors: `unit`, `priority`, `service` and `structured`
  are 9.2 additions that answer 400. Filtering has to happen client-side, and
  the version difference has to be handled before that is worth shipping.
- **Ceph**, on a cluster that runs it: health, pool size and min_size, cephx,
  and OSD encryption. `/cluster/ceph/status` answers `500 binary not installed`
  on a host without it, which is a clean degradation — but every rule would be
  written against a schema and nothing else, so there is no command.
- **Proxmox Backup Server**, on 8007, as a second profile mode — the one place
  where backup retention, verification and encryption can actually be checked
  rather than inferred.

## Also wanted

- Shell completions and a man page.
- Packaging: Homebrew, `.deb`, `.rpm`, the way its UniFi sibling ships.
- A `--since` on [`shadow`](Shadow), for comparing against a snapshot by date
  rather than by path.
