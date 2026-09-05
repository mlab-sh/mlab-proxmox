# `mlab-proxmox posture`

The cluster-wide settings that claim to defend something.

```bash
mlab-proxmox posture
```

```
  Cluster

  shape           standalone node
  quorum          n/a
  migration       type=secure (default)
  fencing         watchdog (default)
  ha              not configured
  mac prefix      BC:24:11
  proxy           none
  consent banner  none
  webauthn        not configured

  Firewall

  datacenter switch  off
  rules              0
  security groups    0
  ip sets            0
  guests             5
```

Every line shows the effective value, with `(default)` when the setting was
never written — because "absent" and "set to the default" are the same thing to
the cluster and very different things to a reader.

## What it grades

Quorum and membership: a lost quorum is the only `critical` this CLI issues on
its own, because pmxcfs goes read-only and nothing starts until it comes back.
An even node count with no tie-breaker is `medium`: it survives no more
failures than the odd number below it, and a clean split leaves neither half
quorate.

Corosync: a single link is a single point of failure for the whole cluster;
traffic that is neither encrypted nor authenticated is `high`.

Migration: `type=insecure` sends guest memory, and everything in it, across the
network in the clear.

The datacenter proxy: an `http_proxy` with credentials in the URL puts a
password in `datacenter.cfg`, readable by anything holding `Sys.Audit`.

And the firewall's master switch, which is off until somebody turns it on.

## On a standalone node

Most of the above does not apply, and the report says so rather than passing
checks that were never relevant:

```
  info
    cluster       this is a standalone node, not a cluster
      No corosync, no quorum, no HA. Everything below about cluster integrity is
      simply not applicable.
```
