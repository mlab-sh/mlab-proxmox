# The token

mlab-proxmox authenticates with a Proxmox **API token**: one HTTP header, no
session, no CSRF, and a credential you can revoke without touching the user it
belongs to.

This page creates a read-only role, a user to hold it, and a token to use it.
Four commands on any node of the cluster.

## The one thing to understand first

A role is never attached to a token. Proxmox has a single mechanism, the
**ACL**, which binds a *subject* (a user, a group or a token) to a *path* with
a *role*. Creating a role changes nothing until an ACL entry hands it to
somebody.

```
  role      a list of privileges          MlabAudit = Sys.Audit, Sys.Syslog, …
  path      what it applies to            /  /nodes/pve1  /vms/150
  subject   who receives it               mlab@pve   or   mlab@pve!audit
```

## Create the role

The seven privileges of the built-in `PVEAuditor` role, plus `Sys.Syslog`,
which is what opens the journal and the firewall logs. All of them are
read-only.

```bash
pveum role add MlabAudit --privs "Sys.Audit,Sys.Syslog,VM.Audit,VM.GuestAgent.Audit,Datastore.Audit,SDN.Audit,Pool.Audit,Mapping.Audit"
```

## Create the user, grant the role, mint the token

```bash
pveum user add mlab@pve && pveum acl modify / --user mlab@pve --role MlabAudit && pveum user token add mlab@pve audit --privsep 0
```

That is the whole setup. The user needs no password: it exists only to hold the
token. `--privsep 0` means the token inherits the user's privileges, and since
the user has nothing but `MlabAudit`, the token has nothing but `MlabAudit`.

The command prints the secret **once**:

```
┌──────────────┬──────────────────────────────────────┐
│ key          │ value                                │
╞══════════════╪══════════════════════════════════════╡
│ full-tokenid │ mlab@pve!audit                       │
├──────────────┼──────────────────────────────────────┤
│ value        │ 3fa85f64-5717-4562-b3fc-2c963f66afa6 │
└──────────────┴──────────────────────────────────────┘
```

There is no way to read it again. Give it to the CLI now:

```bash
mlab-proxmox login --name lab --host 10.0.10.11 --token-id 'mlab@pve!audit'
```

`login` prompts for the secret without echoing it, tests the connection,
records the certificate fingerprint, and writes the profile 0600.

## The other way: privilege separation on

`--privsep 1` (the default for a token created in the GUI) gives the token
**no** privileges of its own. Its effective rights are the intersection of the
user's and the token's, and an empty intersection is empty. This is the trap
that produces a token which authenticates fine and reads nothing:

```bash
pveum user token add mlab@pve audit --privsep 1
pveum acl modify / --tokens 'mlab@pve!audit' --role MlabAudit
```

Two ACL entries, one for the user and one for the token. Worth it when the same
user carries several tokens with different scopes; overkill for a single
read-only integration.

## In the web interface

- **Datacenter → Permissions → Roles → Create**: name `MlabAudit`, then pick
  the eight privileges above.
- **Datacenter → Permissions → Users → Add**: `mlab`, realm `pve`.
- **Datacenter → Permissions → Add → User Permission**: path `/`, user
  `mlab@pve`, role `MlabAudit`, *Propagate* ticked.
- **Datacenter → Permissions → API Tokens → Add**: user `mlab@pve`, Token ID
  `audit`, untick *Privilege Separation*.

If you leave *Privilege Separation* ticked, add one more entry: **Add → API
Token Permission**, path `/`, token `mlab@pve!audit`, role `MlabAudit`.

## Set an expiry

`pveum user token add` inherits the user's expiry, which is usually none. A
token nobody remembers keeps working forever:

```bash
pveum user token add mlab@pve audit --privsep 0 --expire 1798761600
```

The value is Unix epoch seconds; `date -d '+1 year' +%s` produces one.
`mlab-proxmox access check` reports tokens without an expiry — including its
own, if it can read the list.

## Check it worked

```bash
pveum acl list
mlab-proxmox whoami
```

`whoami` is the honest answer, because it asks the cluster what *this* token
may do rather than what you meant to grant:

```
  Token mlab@pve!audit

  /               Datastore.Audit Mapping.Audit Pool.Audit SDN.Audit Sys.Audit Sys.Syslog VM.Audit VM.GuestAgent.Audit
  /access         …
  /nodes          …
  /storage        …
  /vms            …

  8 paths

  Audit coverage at /
  ✔ every PVEAuditor privilege is held at / — the configuration surface is open

  Beyond the auditor role

  ✔ Sys.Syslog  journal, syslog, firewall logs
  · Sys.Modify  pending package updates
      also rewrites host network configuration — grant with care
  · User.Modify  the API tokens of other users
      also grants user administration — grant with care
```

## What stays out of reach, and why

Two reads need a privilege that is not read-only. mlab-proxmox does not ask for
either, and reports the gap rather than pretending the check passed:

| Read | Needs | Why it is not in the role |
| --- | --- | --- |
| Pending package updates | `Sys.Modify` | The same privilege rewrites the host's network configuration. |
| The API tokens of other users | `User.Modify` | The same privilege administers users. |

Grant them on purpose if you want those two checks, knowing the trade:

```bash
pveum role add MlabAuditPlus --privs "Sys.Audit,Sys.Syslog,Sys.Modify,User.Modify,VM.Audit,VM.GuestAgent.Audit,Datastore.Audit,SDN.Audit,Pool.Audit,Mapping.Audit"
```

## Revoking

```bash
pveum user token remove mlab@pve audit
```

The user, the role and the ACL entry survive; only the credential dies. That is
the reason to use a token rather than a password in the first place.
