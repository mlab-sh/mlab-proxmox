# `mlab-proxmox logins`

Who authenticated, who failed, and from where.

```bash
mlab-proxmox logins
mlab-proxmox logins --failed
mlab-proxmox logins --limit 1000 -o json
```

```
  Authentication

  NAME    NODE  USER      SOURCE       STARTTIME         DETAIL
  ok      pve1  root@pam               2026-09-05 16:36  successful auth for user 'root@pam'
  failed  pve1  admin@pve  203.0.113.7  2026-09-05 14:02  authentication failure; rhost=203.0.113.7 …

  2 events
```

The cluster log is the only place in the API where a **failed** authentication
is visible. The task log records what a session did; it never records the
attempts that never became one.

Below the list, the same grouping the audit uses: failures per user and per
source address, `high` once one source passes five — which is where a typo
stops being a plausible explanation.

## The limit worth knowing

`/cluster/log` rotates. Every count here **bounds** what happened rather than
measuring it, and the finding says so in its own words rather than leaving you
to assume otherwise. For a real history, ship the log somewhere that keeps it.
