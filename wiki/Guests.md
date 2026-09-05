# `mlab-proxmox guests`

The virtual machines and containers, and how they are configured.

```bash
mlab-proxmox guests list
mlab-proxmox guests list --running --node pve1
mlab-proxmox guests get 150
mlab-proxmox guests check
mlab-proxmox guests check --vmid 150
mlab-proxmox guests agent
```

`vm` and `vms` are aliases for `guests`; `harden` is an alias for `check`.

## `list`

One call to `/cluster/resources`, which is the cheapest inventory there is.

```
  NAME       VMID  NODE  TYPE  STATUS   UPTIME   MAXDISK    MAXMEM
  web01      150   pve1  qemu  running  12d 04h  50.0 GiB   8.0 GiB
  db01       151   pve1  qemu  running  12d 04h  50.0 GiB   8.0 GiB
  registry01 160   pve1  qemu  running  12d 04h  100.0 GiB  2.0 GiB

  3 guests
```

A template shows `template` in the status column rather than its power state.

## `get`

Identity, network with the VLAN and firewall flag per NIC, the guest firewall
switch, the snapshots, the full configuration, then the hardening checks for
that one guest.

```
  Guest web01 (vm/150)

  node        pve1
  kind        virtual machine
  status      running
  cores       4 core(s)
  memory      8.0 GiB
  protection  off

  Network

  NAME  BRIDGE  FIREWALL  MAC
  net0  vmbr0   0         BC:24:11:…

  Firewall

  enabled     no
  policy in
  policy out
  rules       0
```

## `check`

The hardening catalogue over every guest, or one of them. This is the same set
of rules [`audit`](Audit) runs, on its own so it can be read on its own.

What it looks at, in one sentence each: whether a container is privileged, and
what its `features` let it do; whether a host path is bind-mounted into it;
whether a VM carries raw `args`, a PCI or USB device, a virtiofs share or
shared memory; whether a hook script runs on the node; whether cloud-init
carries a password; whether a NIC is untagged, trunked or filtered; and whether
any snapshot is stale or holds RAM state.

Each one is listed with its identifier in [Checks](Checks).

## `agent`

What the QEMU guest agent reports from inside each guest: operating system,
kernel, hostname, interfaces and open sessions.

```
  NAME            STATUS              OS                    SESSIONS  ADDRESSES
  web01 (vm/150)  answering           Debian GNU/Linux 12   1         3
  db01 (vm/151)   configured, silent                        0         0
```

Two things worth being explicit about. It costs **no packet on the guest
network and no credential inside the machine** — the channel is a virtio serial
port between the host and the guest. And it is the guest describing itself, so
it is an *inventory*, never a verification: a compromised guest answers
whatever it likes.

`configured, silent` is the interesting row, and it is a `medium` finding in
`check`. With `agent: enabled=1`, Proxmox asks the agent to freeze the
filesystem before a snapshot backup. No agent means no freeze, and a backup
taken from a live filesystem that the configuration claims was quiesced.

## The caveat that applies to every other check

`guests check` reads the **stored** configuration. A key changed on a running
guest is staged until the next start, and `guest.pending-changes` names those
keys — for them, the rest of the report describes what will run rather than
what is running.

## The two-switch trap

The most common real finding is not a bad rule, it is two switches that
disagree. A guest firewall is armed by `enable` in its firewall options, and
packets only reach it when the NIC carries `firewall=1`. One without the other
filters nothing, and both spellings of the mistake get a `high`:

```
  firewall.guest-switch-off   a NIC is marked filtered and the guest switch is off
  firewall.nic-unfiltered     the guest switch is on and no NIC is marked filtered
```
