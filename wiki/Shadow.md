# `mlab-proxmox shadow`

What turned up since the last snapshot.

```bash
mlab-proxmox shadow
mlab-proxmox shadow --against /backup/pve/baseline.json
mlab-proxmox shadow --save
```

The same comparison as [`diff`](Diff), with the present as the later side and
the newest snapshot on disk as the earlier one:

```
  › baseline: /Users/you/.mlab/proxmox-snapshots/lab-20260905T170340.json

  Changes between 2026-09-05T17:03:40Z and 2026-09-06T09:12:55Z

  NAME                              TYPE   STATUS     DETAIL
  vm/199                            guest  appeared
  automation@pve!deploy             token  appeared
  user automation@pve Administrator on /  grant  appeared

  3 changes
```

This is the command to put on a schedule. It answers one question — did
anything appear that nobody announced — and it answers it about the things that
matter most: a new guest, a new user, a new token, a new grant.

```bash
# every morning, against last week's baseline
0 8 * * * mlab-proxmox shadow --quiet -o json | mail-if-not-empty
```

## `--save`

Writes the freshly collected state as a new snapshot afterwards, so the next
run compares against today rather than against the original baseline. Without
it, the baseline stays put and the report grows — which is what you want for
"what changed since the audit", and not what you want for "what changed
overnight".

## When there is no baseline

```
  ✖ no snapshot to compare against; run `mlab-proxmox snapshot` once to establish
    a baseline
```
