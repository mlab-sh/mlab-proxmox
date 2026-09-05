# `mlab-proxmox footprint`

What this cluster looks like from outside, and what leaves it.

```bash
mlab-proxmox footprint
```

Five blocks, in the order an outsider would learn them.

**Addresses.** Every configured interface with its CIDR and gateway. A routable
address on a node interface is a `medium` finding: the API on 8006, SPICE on
3128 and the VNC range are reachable from wherever that address is routed,
unless something in front of them says otherwise.

**Certificates.** Subject, issuer, expiry and SANs, per node. Self-signed is
`low`, expiring inside 30 days is `medium`, already expired is `high`.

**Listening, by design.** The ports Proxmox opens, from the documentation.

```
  NAME           SERVICE
  8006/tcp       API and web interface
  3128/tcp       SPICE proxy
  5900-5999/tcp  VNC consoles
  22/tcp         SSH, required between cluster nodes
  5405-5412/udp  corosync, between cluster nodes
  111/tcp        rpcbind, when an NFS storage is configured
  › these are the ports Proxmox opens, not the result of a scan
```

Nothing is probed. This tool does not send a packet at anything, and a list of
ports that came from a document is worth exactly what a document is worth.

**Readable before authentication.** The realm list, because
`GET /access/domains` needs no credentials — anyone who reaches the API learns
which directories authenticate this cluster, and whether any of them enforces a
second factor.

**What leaves the cluster.** Metrics servers shipping to InfluxDB or Graphite,
and webhook or Gotify notification targets. Guest names, sizes, load and task
failure text go out on those paths, continuously, with nobody watching.

```
  NAME          TYPE             ENABLE  TARGET
  mail-to-root  notify/sendmail  1       Send mails to root@pam's email address
```
