# `mlab-proxmox blast`

What one compromised guest reaches.

```bash
mlab-proxmox blast 150
```

```
  Blast radius of web01 (vm/150)

  node                 pve1
  guest firewall       off
  datacenter firewall  off
  segments             net0→vmbr0 untagged

  Reachable at layer 2

  NAME                    NODE  STATUS   BRIDGE  FILTERED  NIC   VLAN
  db01 (vm/151)           pve1  running  vmbr0   no        net0  untagged
  registry01 (vm/160)     pve1  running  vmbr0   no        net0  untagged
  app01 (vm/180)          pve1  running  vmbr0   no        net0  untagged
  app01-staging (vm/181)  pve1  running  vmbr0   no        net0  untagged

  4 guests

  The host, on the same segment

  NAME   CIDR           GATEWAY    COMMENT
  vmbr0  10.0.10.11/24  10.0.10.1  the host answers on this segment: 8006, 22, 3128

  What this means

  high
    vm/150   web01 (vm/150) reaches 4 guest(s) with nothing in between
      The datacenter firewall is off, so no rule at any level applies: every guest on
      these bridges is one ARP away.

  medium
    vm/150   the hypervisor answers on the same segment as this guest
      A compromised guest can reach the API on 8006 and SSH on 22 directly. That is
      where a `management` IPSet and a host firewall rule earn their keep.
```

## What it computes, and what it refuses to guess

The reach is **layer 2**: a guest with a NIC on a bridge reaches every other
guest on that same bridge and VLAN tag, and nothing in the hypervisor stops it
unless the firewall is on at both the datacenter and the guest. `filtered` in
the table is that verdict per neighbour, not a guess.

The host row appears when the bridge carries the node's own address, which is
the usual single-bridge setup — and is why a compromised guest starts one hop
from the management interface.

Everything above layer 2 is the network's business, not Proxmox's. This command
does not model your routers, your upstream ACLs or anything physically attached
to those bridges outside the cluster. It does not follow SDN zones either — no
cluster tested so far runs SDN — and it deliberately says nothing about shared
storage as a lateral path, which is a claim the API cannot support. It states
its own boundary rather than implying the guest is contained:

```
  info
    vm/150   no other guest shares a bridge and VLAN with this one
      Within this cluster. Anything else on those segments physically is outside
      what the API can see.
```

A guest holding a PCI device gets its own line, because a DMA-capable device
escapes the network model entirely and containment then depends on the IOMMU
group.
