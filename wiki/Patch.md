# `mlab-proxmox patch`

Where updates would come from, and what is waiting.

```bash
mlab-proxmox patch
```

```
  Patch state

  NAME  KERNEL        SUBSCRIPTION  UPDATES     VERSION
  pve1  6.17.2-1-pve  notfound      unreadable  9.1.1

  Repositories on pve1

  NAME                            ENABLE  FILE                    SUITE            URI
  enterprise                      false   ceph.sources            trixie           https://enterprise.proxmox.com/…
  main contrib non-free-firmware  true    debian.sources          trixie           http://deb.debian.org/debian/
  main contrib non-free-firmware  true    debian.sources          trixie-security  http://security.debian.org/…
  pve-enterprise                  false   pve-enterprise.sources  trixie           https://enterprise.proxmox.com/…

  Patch checks

  high
    node/pve1     no Proxmox repository is enabled
      Nothing on this node will ever receive a Proxmox update.
```

That finding is the common one on a freshly installed host: the enterprise
repository is disabled because there is no subscription, and nobody enabled
`pve-no-subscription` in its place. Debian security updates keep arriving;
Proxmox ones never do.

## The three repository states worth knowing

| State | Verdict |
| --- | --- |
| enterprise enabled, no subscription | `high` — every `apt update` fails 401 |
| no Proxmox repository at all | `high` — no Proxmox update will ever land |
| a `*test` repository enabled | `medium` — test packages on a machine somebody depends on |

Third-party repositories are listed as `low`: their maintainer can install
anything on the host at the next upgrade, which is worth knowing about even
when it is intentional.

## Pending updates need a privilege this CLI will not ask for

`GET /nodes/{node}/apt/update` requires `Sys.Modify` — the same privilege that
rewrites the host's network configuration. The recommended role does not carry
it, so the column reads `unreadable` and the report says so:

```
  unreadable
    node/pve1     the pending update list cannot be read
      → Grant Sys.Modify on the node if you accept that trade, or check with
        `pveversion -v` over SSH.
```

Grant it deliberately if you want that check. See [Token](Token).
