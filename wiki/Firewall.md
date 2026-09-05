# `mlab-proxmox firewall`

The firewall, at each of the four levels that can turn it off. `fw` is an alias.

```bash
mlab-proxmox firewall status
mlab-proxmox firewall rules
mlab-proxmox firewall objects
mlab-proxmox firewall log
mlab-proxmox firewall check
```

## `status`

The one view that answers "is anything actually filtered".

```
  Datacenter

  firewall        off
  policy in       DROP (default)
  policy out      ACCEPT (default)
  policy forward  DROP (default)
  ebtables        on
  rules           0

  Hosts

  NAME  ENABLE  ENGINE    LOG_LEVEL_IN  RULES  SYNFLOOD  TCPFLAGS
  pve1  on      iptables  nolog         0      off       off

  Guests

  NAME              ENABLE  FILTERED  MACFILTER  NICS  POLICY_IN       RULES
  web01 (vm/150)    off     0         on         1     DROP (default)  0
  db01 (vm/151)     off     0         on         1     DROP (default)  0

  ! the datacenter switch is off, so none of the above filters anything
```

Four levels, four switches, and they have to agree:

| Level | Switch | Default |
| --- | --- | --- |
| Datacenter | `enable` in cluster firewall options | **off** |
| Host | `enable` in the node's firewall options | on |
| Guest | `enable` in the guest's firewall options | off |
| NIC | `firewall=1` on `netN` in the guest config | off |

The datacenter switch being off by default is the one that surprises people: a
cluster nobody has configured has rules, zones and a whole UI, and no packet
filter.

## `rules`

Every rule at every level that carries one, with its position, action, protocol,
destination port, source and log level. `source` reads `any` when the rule does
not restrict it, because an empty cell is easy to skim past.

## `objects`

IP sets with their members, aliases, and security groups. The `management` IP
set is the one that decides who may reach 8006, 22 and 3128 once the firewall
is on; its absence is a `low` finding, and a `0.0.0.0/0` inside it is a `high`
one — a set that contains a default route restricts nothing.

Security groups are read in full. A rule of type `group` is only a reference,
and the ACCEPTs live inside the group, so `check` runs the same hygiene over
each group's rules and attributes what it finds to `group/<name>`. Without
that, a cluster that organises its firewall properly would be the one audited
least.

## `log`

```bash
mlab-proxmox firewall log --limit 200
mlab-proxmox firewall log --node pve1 -o json
```

What the host firewall is actually dropping. This needs `Sys.Syslog`, which is
in the role this CLI recommends — see [Token](Token). The **per-guest** log is
the one that stays out of reach: it needs `VM.Console`, and console access to
every guest is too high a price for a log tail.

An empty log while the firewall is on usually means every level is at `nolog`,
which is its own finding (`firewall.no-logging`).

## `check`

The graded checks: the switches, the default policies, rules that accept from
anywhere or log nothing, disabled rules, MAC filtering, router advertisements,
and forward rules on a node running the iptables engine.

That last one is worth knowing about. Proxmox ships two firewall
implementations, and rules in the **forward** direction only take effect under
the nftables-based `proxmox-firewall`. The stock `pve-firewall` accepts them
into the configuration and ignores them — a rule that reads as protection and
is not one.

## What it does not do

**Ordering.** Whether rule #3 shadows rule #7 depends on the full match
semantics of the engine in use, and a wrong answer there is worse than no
answer. `firewall.duplicate-rule` reports rules that are *identical* — same
action, protocol, ports, source, destination and interface — and says nothing
about which one wins.

**The compiled ruleset.** No API route exposes `iptables-save` or the nftables
set, so everything here reads the configuration. If the service was not
reloaded, or somebody added a rule by hand on the host, the difference is
invisible from the API.
