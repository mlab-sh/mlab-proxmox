# `mlab-proxmox audit`

Every graded check in one report. Start here.

```bash
mlab-proxmox audit
mlab-proxmox audit --min high
mlab-proxmox audit --fail-on high
mlab-proxmox audit -o json > audit.json
```

One collection pass over everything the token can read, then every rule in
[Checks](Checks) over that data. The collection and the rules are separate on
purpose: the rules are pure functions, so each one is tested against a literal
rather than against a cluster.

```
  Audit of lab (https://10.0.10.11:8006/api2/json)

  high
    cluster       no backup job exists, for 5 guest(s)
      Nothing is scheduled: every guest on this cluster is one mistake from gone.
      → Datacenter → Backup → Add.
    cluster       the cluster firewall is off
      `enable` is unset at the datacenter level, so no rule anywhere takes effect —
      including the 0 rule(s) and any per-guest rule already written.
      → Datacenter → Firewall → Options → Firewall: Yes. Create the `management` IPSet
      first, or you will lock yourself out of 8006.
    node/pve1     no Proxmox repository is enabled
      Nothing on this node will ever receive a Proxmox update.
    user/root@pam  root@pam has no second factor

  medium
    user/ops@pve  ops@pve has no second factor

  low
    vm/150        web01 (vm/150) can be deleted while it runs
    …

  4 high   1 medium   6 low   14 info   2 unreadable

  2 route(s) could not be read; the checks behind them report nothing, which is not the same as passing:
    /nodes/pve1/apt/update  API error 403: Permission check failed (/nodes/pve1, Sys.Modify)
    /access/users/ops%40pve/token  API error 403: Permission check failed
```

Findings are sorted worst first, then by subject so everything about one guest
stays together. Each carries a stable identifier in JSON, a detail explaining
*why* it is a finding, and — where there is one — the remedy, in the words the
web interface uses.

## The footer is part of the report

The last block lists what the collection could not read. A check that was
refused its data reports nothing, and nothing looks exactly like clean. That
list is the difference between the two, and `--min` never hides it.

## Flags

| Flag | Effect |
| --- | --- |
| `--min LEVEL` | Hide findings below this severity. `unreadable` is always shown. |
| `--fail-on LEVEL` | Exit 2 when a finding at this level or worse exists. |

```bash
# in cron, or in CI
mlab-proxmox audit --fail-on high --quiet -o json > /var/log/mlab/audit-$(date +%F).json
```

Exit 0 means the command ran, not that the cluster is clean. Only `--fail-on`
turns findings into an exit code.

## What it does not do

No ordering analysis on firewall rules: a verdict on which rule shadows which
needs the full match semantics of both engines, and a wrong one is worse than
none. No claim about a check whose data was refused. No writes, ever.
