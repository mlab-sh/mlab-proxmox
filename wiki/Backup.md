# `mlab-proxmox backup`

What is protected, by what, and when it last worked.

```bash
mlab-proxmox backup coverage
mlab-proxmox backup jobs
mlab-proxmox backup history
mlab-proxmox backup check
```

## `coverage`

Which guests a job covers, and which none does. The hard part is computed by
the API itself, at `/cluster/backup-info/not-backed-up`:

```
  NAME        VMID  NODE  TYPE  STATUS
  web01       150   pve1  qemu  uncovered
  db01        151   pve1  qemu  uncovered
  registry01  160   pve1  qemu  covered

  3 guests
  ! 2 guest(s) are in no backup job
```

## `jobs`

Schedules, targets, mode, selection, and the retention policy of each job
underneath.

```
  NAME    ID          ENABLE  STORAGE  SCHEDULE      NEXT-RUN          MODE      SELECTION
  nightly backup-4f1  1       pbs      02:30         2026-09-06 02:30  snapshot  all guests

  Retention

  backup-4f1  keep-daily=7,keep-weekly=4,keep-monthly=6
```

## `history`

The `vzdump` and verification tasks that actually ran, with their outcome. A
job is an intention; this is the evidence.

```
  ! no backup task appears in the visible task log
```

The task log is finite, so an empty history is evidence rather than proof.

## `check`

Coverage, plus job health and the storage underneath:

- no job at all, when guests exist
- guests no job covers
- a job that is disabled, or whose retention keeps a single copy
- a job writing to **local** storage — a backup on the node it protects
  survives a deleted guest and nothing else
- a PBS target used without a pinned fingerprint
- backup tasks that failed, or a last success older than two weeks
- no storage accepting `backup` content at all
