# `mlab-proxmox nodes`

The hosts of the cluster, and what they run.

```bash
mlab-proxmox nodes list
mlab-proxmox nodes get pve1
mlab-proxmox nodes check
```

## `list`

```
  NAME  STATUS  UPTIME   CPU   MAXCPU  MAXMEM    MEM
  pve1  online  12d 04h  1.5%  16      64.0 GiB  38.5 GiB
```

`cpu` is a load fraction in the API, where 1.0 means one core saturated; it is
rendered as a percentage of one core, not of the machine.

## `get`

Everything host-level in one page: release and kernel, CPU and memory,
subscription, DNS and timezone, then the services, the network interfaces, the
disks with their SMART verdict, and the certificates with their expiry. It
finishes with the graded checks that apply to that host.

```
  Node pve1

  release       Proxmox VE 9.1.1
  kernel        6.17.2-1-pve (efi boot)
  cpu           Intel(R) Core(TM) i7-8700 × 16
  memory        38.5 GiB of 64.0 GiB used
  subscription  notfound
  dns           10.0.10.53
  timezone      Etc/UTC

  Services

  NAME          STATE    ENABLED  DESC
  corosync      stopped  enabled  Corosync Cluster Engine
  pve-firewall  running  enabled  Proxmox VE firewall
  pveproxy      running  enabled  PVE API Proxy Server
  …

  Network

  NAME    TYPE    STATE   CIDR            GATEWAY    BRIDGE_PORTS
  vmbr0   bridge  active  10.0.10.11/24   10.0.10.1  enp1s0
  …

  Disks

  NAME       TYPE  MODEL           SIZE      HEALTH  USED
  /dev/nvme0n1  nvme  Samsung SSD  894.3 GiB  PASSED  LVM
  …

  Certificates

  NAME             ISSUER                          NOTAFTER          KEYTYPE  KEYBITS
  pve-root-ca.pem  /CN=Proxmox Virtual Environment  2035-01-14 09:20  rsa      4096
  pve-ssl.pem      /CN=Proxmox Virtual Environment  2027-01-16 09:20  rsa      2048
```

## `check`

The host checks over every node at once, without the inventory: certificates,
services, clock drift, disk health, public addresses, repositories,
subscription and pending updates. Same rules as the corresponding sections of
[`audit`](Audit).

## A note on the certificate

`pveproxy-ssl.pem` is the certificate an operator installed. When there is none
— the usual case — pveproxy serves `pve-ssl.pem`, issued by the cluster's own
CA. Whichever of the two exists is the one a browser sees, and the one the
self-signed check looks at.
