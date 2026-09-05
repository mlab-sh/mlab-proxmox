# `mlab-proxmox diff`

What changed between two snapshots.

```bash
mlab-proxmox diff before.json after.json
mlab-proxmox diff --all before.json after.json
```

```
  Changes between 2026-09-01T03:00:00Z and 2026-09-05T03:00:00Z

  NAME              TYPE        STATUS       DETAIL
  vm/182            guest       appeared
  ci@pve            user        appeared
  user ci@pve PVEVMAdmin on /vms  grant  appeared
  vm/150            guest       changed      net0: virtio=…,bridge=vmbr0 → virtio=…,bridge=vmbr0,tag=20
  backup-4f1        backup job  disappeared

  5 changes
```

Presence for inventory, field by field for configuration. Ten collections are
tracked by identity: guests, users, tokens, ACL grants, roles, storages, backup
jobs, **firewall rules, IP sets and security groups** — plus a handful of single
values that matter on their own: the release, the datacenter firewall switch and
its inbound policy, the migration mode and the HTTP proxy.

A firewall rule has no stable identity of its own — `pos` shifts the moment
anything is inserted above it — so the rule *is* its own key: action, protocol,
ports, source, destination and interface. Moving a rule is therefore not a
change; adding, removing or editing one is.

Whole node configuration is deliberately **not** diffed. A node object is
dominated by live metrics — load, memory, disk wear, package lists — and
comparing it produces a change on every run, which is the fastest way to make a
diff unreadable.

## What it deliberately ignores

Live counters. `uptime`, `cpu`, `mem`, `disk`, `netin`, `netout`, `status`,
`avail`, `used` and `next-run` change on every read and would drown a real
change in noise.

Field order. Several fields come back as an unordered set — a storage's
`content` list reorders between two identical reads — so comma-separated values
are compared as sets rather than as strings.

## What it refuses to do

Compare across a blind spot. Both snapshots record which routes were refused,
and if either one could not read a collection, the diff says so rather than
reporting everything in it as disappeared:

```
  ! the before snapshot has 2 unreadable route(s); anything they cover is not compared
```

That is the failure mode this design exists to avoid: a token that lost a
privilege between two runs looks, to a naive diff, exactly like an
infrastructure that was deleted.

## `--all`

Also lists what did not change, which is occasionally what you want to prove.
