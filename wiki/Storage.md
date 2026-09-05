# `mlab-proxmox storage`

What the cluster stores things on.

```bash
mlab-proxmox storage list
mlab-proxmox storage check
```

## `list`

The definitions joined to live usage, which lives per node rather than on the
definition:

```
  NAME       TYPE     STATUS     AVAIL      CONTENT                   SHARED  TOTAL
  local      dir      available  40.0 GiB   vztmpl,backup,iso,import  0       64.0 GiB
  vmstore     lvmthin  available  300.0 GiB  rootdir,images            0       512.0 GiB
  local-lvm  lvmthin  available  80.0 GiB   images,rootdir            0       160.0 GiB

  3 storages
```

`GET /storage` returns the full configuration of every storage the token can
see — `Datastore.Audit` is enough, the per-storage detail route that needs
`Datastore.Allocate` adds nothing this CLI wants.

Storage credentials are not in there: Proxmox keeps them in `/etc/pve/priv`,
which no API route exposes.

## `check`

- a storage that is disabled but still configured, and still referenced by
  whatever used it
- a Proxmox Backup Server used without a pinned `fingerprint`, which means the
  client accepts whichever host answers on that address
- NFS and CIFS shares, noted because their access control is the server's
  rather than Proxmox's
- no storage accepting `backup` content anywhere in the cluster
