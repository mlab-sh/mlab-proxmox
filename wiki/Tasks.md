# `mlab-proxmox tasks`

Who did what on this cluster, and whether it worked.

```bash
mlab-proxmox tasks
mlab-proxmox tasks --failed
mlab-proxmox tasks --kind vzdump --limit 20
mlab-proxmox tasks --user root@pam
mlab-proxmox tasks --follow
```

```
  NODE  TYPE       STATUS  STARTTIME         USER
  pve1  vncshell   OK      2026-09-05 16:36  root@pam
  pve1  aptupdate  OK      2026-09-05 00:25  root@pam
  pve1  vzdump     OK      2026-09-04 02:30  root@pam

  3 tasks
```

The task log is the only history the API keeps: every start, stop, backup,
migration, console session and configuration change, with the user that asked
for it. It is finite, so the absence of a task is not the absence of an event.

Filters are pushed to the server. `/cluster/tasks` takes no parameters and
returns a short tail, so this reads `/nodes/{node}/tasks` on every node instead
— which accepts `limit`, `errors`, `typefilter` and `userfilter` — and merges
the results newest first.

## `--follow`

```bash
mlab-proxmox tasks --follow --interval 5
```

Polling, and honest about it: there is no event stream in the Proxmox API — the
web interface polls too. The first pass establishes a baseline rather than
replaying history; after that, each new task prints as it appears. `^C` stops.

```
  › watching 50 task(s) every 10s; ^C to stop
  2026-09-05T17:22:04Z  qmstart     150  OK
  2026-09-05T17:22:31Z  vncproxy    150  !! connection failed
```

With `-o json`, one object per line, which is what a log shipper wants.

## Useful shapes

```bash
# what failed today
mlab-proxmox tasks --failed --limit 100

# every console session ever opened, and by whom
mlab-proxmox tasks --kind vncshell --limit 200

# is anything running right now
mlab-proxmox tasks -o json | jq '.[] | select(.status=="running")'
```
