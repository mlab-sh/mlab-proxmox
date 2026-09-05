# Surfaces

Unlike a UniFi console, Proxmox answers on exactly one API. No legacy surface,
no undocumented v2 the web app keeps for itself: the GUI drives the same routes
this CLI does, and the schema that generates the
[API viewer](https://pve.proxmox.com/pve-docs/api-viewer/) ships with the
product.

```
https://<host>:8006/api2/json/<path>      JSON, what this CLI speaks
                   /api2/extjs/…          the same data in an ExtJS envelope
                   /api2/html|text/…      human formats
```

## The shape of a response

Everything is wrapped in `{"data": …}`, which the client unwraps before a
command ever sees it. Nothing paginates: a list endpoint returns everything.

A failure carries the explanation in the HTTP status and, for a bad parameter,
in an `errors` map naming the field:

```
API error 400: Parameter verification failed.
  vmid: invalid format
```

401 means the token id or its secret is wrong. 403 means the token
authenticated and lacks a privilege — `mlab-proxmox whoami` says which.

## One node reaches the cluster

`pveproxy` forwards a request for `/nodes/other/…` to the node that owns it, so
a profile is a cluster rather than a machine. That is also why `login` records
which node answered: the certificate belongs to that one.

## The census

Read from the PVE 9.2 schema, in full: **447 paths**, **678 endpoints**
(341 GET, 175 POST, 83 PUT, 79 DELETE). This CLI only ever issues GETs.

| Subtree | GET routes | What is in there |
| --- | --- | --- |
| `/nodes/*` | 189 | per-host everything: status, network, services, disks, certificates, apt, tasks, journal, firewall, and the guests |
| `/cluster/*` | 128 | the shared configuration: resources, status, options, corosync, firewall, HA, backup jobs, replication, SDN, notifications, metrics |
| `/access/*` | 19 | users, groups, roles, ACL, realms, TFA, tokens, and the caller's own permissions |
| `/storage`, `/pools`, `/version` | 5 | storage definitions, resource pools, the version banner |

Three reads answer a whole question in one call, and most of this CLI is built
on them: `/cluster/resources` (every node, guest and storage with live state),
`/cluster/backup-info/not-backed-up` (guests no job covers, computed by the
API), and `/access/permissions` (what the calling token may do).

## Authentication

Two mechanisms; this CLI uses the first.

**API token.** One header, stateless, no CSRF:

```
Authorization: PVEAPIToken=user@realm!tokenname=<uuid>
```

**Ticket.** `POST /access/ticket` returns a cookie plus a
`CSRFPreventionToken` required on every write, and supports TFA challenges.
Exactly five endpoints refuse a token and need one: `POST /access/ticket`,
`PUT /access/password`, and the three `/access/tfa/{userid}` mutations. Console
and VNC websocket routes additionally demand a real user. None of it is
read-only, so none of it is missed.

See [Token](Token) for creating one.

## Permissions

Role on path, with inheritance. An ACL entry binds a user, group or token to a
role at a path — `/`, `/nodes/pve1`, `/vms/150`, `/storage/local` — and
`propagate` pushes it down the tree. Roles are bags of privileges.

The built-in read-only role, read from `pve-access-control` rather than from
the documentation, is exactly seven privileges:

```
PVEAuditor = Sys.Audit · VM.Audit · VM.GuestAgent.Audit · Datastore.Audit
           · SDN.Audit · Pool.Audit · Mapping.Audit
```

Classifying all 341 GET routes against a token holding that role at `/` with
propagate:

| | Routes | |
| --- | --- | --- |
| covered by an audit privilege | 188 | the configuration surface |
| open to any authenticated user | 117 | server-side filtered to what you may see |
| need a privilege the role lacks | 34 | see below |
| readable before authentication | 2 | `/access/ticket`, `/access/domains` |

That second pre-auth route matters: the **realm list is world-readable** so the
login box can render it, which means anyone who reaches port 8006 learns which
directories authenticate the cluster. `mlab-proxmox footprint` says so.

## What the auditor role cannot read

Grouped by the privilege that would unlock it, with the judgement this CLI
makes about each.

| Privilege | Unlocks | Verdict |
| --- | --- | --- |
| `Sys.Syslog` | journal, syslog, host and ceph firewall logs | **worth it**, read-only by nature — it is in the role this CLI recommends |
| `Sys.Modify` | pending package updates, apt changelog | **no**: the same privilege rewrites host network configuration |
| `User.Modify` | the API tokens of other users | **optional**: real audit value, but it grants user administration |
| `VM.Console` | per-guest firewall logs, VNC websockets | **no**: console access to every guest for a log tail |
| `Datastore.Allocate` | per-storage detail, the `scan/*` discovery routes | **not needed**: `GET /storage` already returns the full config |
| `SDN.Allocate` | per-object zone, controller, DNS and IPAM config | partial: the index routes still list them |

Two of those gaps are reported as `unreadable` findings rather than silently
skipped. See [Checks](Checks).

## One documented claim that the source contradicts

`GET /access/acl` is documented as "restricted to objects where you have rights
to modify permissions", which would make an ACL audit impossible for a
read-only token. The implementation says otherwise: `Sys.Audit` on `/access`
returns the entire tree. Verified on a live cluster — `mlab-proxmox access acl`
works with nothing but `MlabAudit`.

## There is no event stream

Nothing in the API pushes. The websocket routes are console and migration
tunnels; the web interface polls. Detection here is therefore **differential**:
you compare two dated records rather than receive an alert. That is what
[`snapshot`](Snapshot), [`diff`](Diff) and [`shadow`](Shadow) are for, and why
[`tasks --follow`](Tasks) is honestly described as a poller.

## Ports

What Proxmox opens, from the documentation — not the result of a scan:

| Port | Service |
| --- | --- |
| 8006/tcp | API and web interface |
| 3128/tcp | SPICE proxy |
| 5900-5999/tcp | VNC consoles |
| 22/tcp | SSH, required between cluster nodes |
| 5405-5412/udp | corosync, between cluster nodes |
| 111/tcp | rpcbind, when an NFS storage is configured |
| 8007/tcp | a Proxmox Backup Server, if one sits alongside |

## Reaching a route by hand

```bash
mlab-proxmox api GET /version
mlab-proxmox api GET /cluster/resources --list
mlab-proxmox api GET /nodes/pve1/qemu/150/config
mlab-proxmox api GET /nodes/pve1/tasks --query limit=20 --list
```

See [api](Api).
