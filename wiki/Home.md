# mlab-proxmox

**A CLI over the Proxmox VE REST API, built as a base for passive
infrastructure security work.**

It talks to any node of a cluster over `https://<host>:8006/api2/json`, with an
API token in one header, and a profile in `$HOME/.mlab/proxmox.conf` says which
cluster to reach and how.

It reads. Nothing in this tool changes a configuration, no command writes to the
cluster, and no data leaves your machine.

---

## The commands

| Command | What it does |
| --- | --- |
| [`audit`](Audit) | Every graded check in one report. Start here. |
| [`snapshot`](Snapshot) | One dated, secret-free record of everything the token can read. |
| [`diff`](Diff) | What changed between two snapshots. |
| [`shadow`](Shadow) | What turned up since the last snapshot. |
| [`login`](Login) | Create or update a profile, prove the token works, save it. |
| [`ping`](Ping) | Check that the current profile reaches its cluster. |
| [`whoami`](Whoami) | What this token is, and everything it is allowed to read. |
| [`nodes`](Nodes) | The hosts: hardware, services, certificates, disks. |
| [`guests`](Guests) | The virtual machines and containers, and their hardening. |
| [`storage`](Storage) | What the cluster stores things on. |
| [`access`](Access) | Users, tokens, roles and the access control list. |
| [`firewall`](Firewall) | The four levels, and whether they agree with each other. |
| [`backup`](Backup) | Coverage, jobs, history. |
| [`patch`](Patch) | Repositories, subscription, pending updates. |
| [`posture`](Posture) | The cluster-wide settings that claim to defend something. |
| [`footprint`](Footprint) | What this cluster looks like from outside. |
| [`blast`](Blast) | What one compromised guest reaches. |
| [`tasks`](Tasks) | Who did what, and whether it worked. |
| [`logins`](Logins) | Who authenticated, who failed, and from where. |
| [`api`](Api) | Raw request against any path, for what is not wrapped yet. |
| [`profile`](Configuration) | List, show, select and delete saved clusters. |
| [`config`](Configuration) | Where the config file is, and what is in it. |

Every command renders to the terminal by default and to raw JSON with
`-o json`. See [Output](Output).

## Key concepts

- **[Token](Token)** — how to create the read-only role and the API token this
  CLI authenticates with. Start here, it takes four commands.
- **[Surfaces](Surfaces)** — one API, one credential, 447 paths, and the
  permission model that decides which of them answer.
- **[Configuration](Configuration)** — profiles, and the precedence between
  flags, environment and file.
- **[Output](Output)** — a terminal render by default, raw JSON with `-o json`,
  and the rules that keep the two from mixing.
- **[Checks](Checks)** — the catalogue of graded findings, what each one means,
  and its identifier.
- **[Passive security](Passive-Security)** — what a read-only token supports in
  defensive work, without sending a packet at anything.
- **[Roadmap](Roadmap)** — what is built, what is next.
- **[Releasing](Releasing)** — how a version becomes a Homebrew formula, a
  `.deb` and an `.rpm`.

## Getting started

```bash
cargo build --release
./target/release/mlab-proxmox login --name lab --host 10.0.10.11 --token-id 'mlab@pve!audit'
./target/release/mlab-proxmox ping
./target/release/mlab-proxmox audit
```

## Scope and stability

The Proxmox VE API is documented, versioned and self-describing, which makes
this tool a great deal simpler than its UniFi sibling: one base URL, one
envelope, no pagination, no undocumented surface to fall back on. What varies
is the Proxmox version — SDN fabrics, HA rules and the nftables firewall are
recent, and a 7.x or 8.x cluster answers 404 on some of it. Every command
treats a 404 as "not on this version" and says so, rather than failing.
