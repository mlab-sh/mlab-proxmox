# `mlab-proxmox snapshot`

One dated, secret-free record of everything the token can read.

```bash
mlab-proxmox snapshot
mlab-proxmox snapshot --out /backup/pve/2026-09-05.json
mlab-proxmox snapshot --stdout | jq '.guests | length'
```

```
  ✔ wrote /Users/you/.mlab/proxmox-snapshots/lab-20260905T170340.json

  acl         1
  backupJobs  0
  collected   2026-09-05T17:03:40Z
  endpoint    https://10.0.10.11:8006/api2/json
  guests      5
  nodes       1
  storages    3
  unreadable  2
  users       2

  ! 2 route(s) were refused and are recorded as unreadable in the file
```

## Why this comes before everything else

There is no event stream and no alert endpoint in the Proxmox API. The way to
notice a change is to have written down what things looked like before. Every
other command in this CLI reads the present; this is the one that gives it a
past, and [`diff`](Diff) and [`shadow`](Shadow) are what read it back.

Detection built this way is slower than a signature and much harder to evade:
an attacker can avoid triggering a rule, but can hardly avoid existing in the
inventory.

## What is in the file

Everything one collection pass reads: version, cluster status and resources,
datacenter options, corosync, every node with its services, network,
certificates, disks, repositories and firewall, every guest with its config,
firewall, rules and snapshots, storages, backup jobs, uncovered guests,
replication, HA, metrics servers, notification targets, SDN, the whole access
control tree, and the recent task log.

Plus, deliberately, the list of routes that were refused — so a later diff
knows the difference between something that disappeared and something that was
never readable.

## What is not

Secrets are blanked on write, at any depth, by key name: anything containing
`password`, `secret`, `privatekey`, `private-key`, `token_secret` or `csrf`
becomes `(redacted)`. Certificate bodies (`pem`) and config digests are dropped
outright — they are bulky, they change whenever anything does, and the
fingerprint already says what changed.

The file still describes your infrastructure in detail. Treat it accordingly.

## Where it goes

`$HOME/.mlab/proxmox-snapshots/<profile>-<timestamp>.json` by default, which is
also where [`shadow`](Shadow) looks for the newest one. `--out` puts it
anywhere; `--stdout` prints it instead, for a pipeline that stores it itself.

```bash
# a weekly baseline, kept out of the way
0 3 * * 1 mlab-proxmox snapshot --quiet
```
