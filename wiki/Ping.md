# `mlab-proxmox ping`

Check that the current profile reaches its cluster, and report what is on the
other end.

```bash
mlab-proxmox ping
mlab-proxmox -p lab ping
```

```
  ✔ answered in 1.2s

  profile      lab
  endpoint     https://10.0.10.11:8006/api2/json
  release      Proxmox VE 9.1.1
  answered by  pve1
  cluster      standalone node
  tls          not verified
```

Two calls: `/version`, then `/cluster/status` for the shape of the cluster.
On a real cluster the last two lines read differently:

```
  answered by  pve2
  cluster      lab — 3/3 node(s) online, quorate
```

A cluster that has lost quorum says so loudly, because nothing else will work
until it comes back:

```
  ! the cluster has no quorum; configuration is read-only until it returns
```

This is the command to run first when something else misbehaves: it separates a
network problem from a credential problem, and it names the exact endpoint in
use, which is often the surprise.

## JSON

```bash
mlab-proxmox ping -o json
```

```json
{
  "profile": "lab",
  "endpoint": "https://10.0.10.11:8006/api2/json",
  "version": "9.1.1",
  "node": "pve1",
  "nodes": 1,
  "nodesOnline": 1,
  "quorate": null,
  "tlsVerified": false,
  "elapsed": "1.2s"
}
```

Suitable for a health check: exit 0 with a parsable body, or exit 1 with a
message on stderr. `quorate` is `null` on a standalone node, which is not the
same as `false`.
