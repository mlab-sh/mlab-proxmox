# `mlab-proxmox api`

Raw request against any path, for everything the CLI does not wrap.

```bash
mlab-proxmox api GET /version
mlab-proxmox api GET /cluster/resources --list
mlab-proxmox api GET /nodes/pve1/qemu/150/config
mlab-proxmox api GET /nodes/pve1/tasks --query limit=20 --list
mlab-proxmox api GET /nodes/pve1/journal --query lastentries=50
```

This is the lab bench. Try an endpoint here, and once it earns its place, it
gets a module of its own.

`PATH` is relative to `/api2/json` and starts with a slash. A path pasted from
the API viewer or from `pvesh` keeps working: a leading `/api2/json` or
`/api2/extjs` is stripped.

## Flags

| Flag | Effect |
| --- | --- |
| `--list` | Render an array response as a table instead of a block. |
| `--limit N` | With `--list`, stop after N rows. |
| `--query K=V` | A query parameter, repeatable. No short form: `-q` is the global `--quiet`. |
| `-d, --data JSON` | A request body: inline, `@file`, or `-` for stdin. |

## It will happily write

Every other command in this CLI reads. This one sends whatever method you give
it, so `POST`, `PUT` and `DELETE` all work and all do what they say. Nothing
guards them beyond your token's own privileges — which, with the role from
[Token](Token), refuses every one of them.

## Where to look next

The full route list is at
[pve.proxmox.com/pve-docs/api-viewer](https://pve.proxmox.com/pve-docs/api-viewer/).
[Surfaces](Surfaces) has the census: 447 paths, which subtree holds what, and
which 34 reads a read-only token cannot reach.
