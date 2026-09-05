# `mlab-proxmox access`

Who can reach this cluster, with what, and for how long.

```bash
mlab-proxmox access users
mlab-proxmox access tokens
mlab-proxmox access roles
mlab-proxmox access acl
mlab-proxmox access realms
mlab-proxmox access check
```

## `users`

```
  NAME      TYPE  ENABLE  EXPIRE  TFA    GROUPS
  ops@pve   pve   1       0       false
  root@pam  pam   1       0       false

  2 users
```

`tfa` is computed by joining the user list to `/access/tfa`, which only lists
an account once a factor is registered. `expire` of 0 means never.

## `tokens`

Privilege separation and expiry, per token. Listing another user's tokens needs
`User.Modify`, which the recommended read-only role does not carry, so this
usually shows only the token you are authenticating with:

```
  ! listing another user's tokens needs User.Modify; only this token's owner is shown
```

That is reported as an `unreadable` finding rather than as a clean result. See
[Token](Token) for the trade.

## `roles`

Every role with how many privileges it carries, then the custom ones in full —
because a custom role's privilege list is the whole point and does not fit in a
column.

```
  NAME       TYPE      PRIVILEGES
  MlabAudit  custom    8
  PVEAdmin   built-in  38
  …

  Custom roles in full

  MlabAudit  Datastore.Audit Mapping.Audit Pool.Audit SDN.Audit Sys.Audit Sys.Syslog VM.Audit VM.GuestAgent.Audit
```

## `acl`

The access control list: who holds which role, where, and whether it
propagates.

```
  NAME     TYPE  PATH  PROPAGATE  ROLE
  ops@pve  user  /     1          MlabAudit

  1 grant
```

`root@pam` never appears here: it is Administrator implicitly, not through an
ACL entry.

The documentation says this list is restricted to objects where you may modify
permissions. The implementation returns the whole tree to anything holding
`Sys.Audit` on `/access` — which is why this works with a read-only token. See
[Surfaces](Surfaces).

## `realms`

The authentication backends, and a reminder that this particular list needs no
credentials at all: `GET /access/domains` is world-readable so the login box can
render it.

## `check`

The graded checks: administrative grants and how far they propagate, custom
roles that are not read-only, accounts with no second factor, tokens without
privilege separation or without an expiry, expired accounts still enabled, and
LDAP or AD realms that do not enforce a factor.

`root@pam` without a second factor is `high` rather than `medium`, because it
is the account that always exists and always has everything.
