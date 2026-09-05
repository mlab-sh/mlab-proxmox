# `mlab-proxmox whoami`

What this token is, and everything it is allowed to read.

```bash
mlab-proxmox whoami
mlab-proxmox whoami --path /vms
```

Every other command's honesty rests on this one. A check that reports nothing
because the token was refused the data must not read as a pass, and this is
where you find out which of the two you are looking at.

```
  Token mlab@pve!audit

  /               Datastore.Audit Mapping.Audit Pool.Audit SDN.Audit Sys.Audit Sys.Syslog VM.Audit VM.GuestAgent.Audit
  /access         Datastore.Audit Mapping.Audit Pool.Audit SDN.Audit Sys.Audit Sys.Syslog VM.Audit VM.GuestAgent.Audit
  /access/groups  …
  /nodes          …
  /pool           …
  /sdn            …
  /storage        …
  /vms            …

  8 paths

  Audit coverage at /
  ✔ every PVEAuditor privilege is held at / — the configuration surface is open

  Beyond the auditor role

  ✔ Sys.Syslog  journal, syslog, firewall logs
  · Sys.Modify  pending package updates
      also rewrites host network configuration — grant with care
  · User.Modify  the API tokens of other users
      also grants user administration — grant with care
```

The paths come from `GET /access/permissions`, which is the cluster's own
answer about *this* credential — not what you meant to grant, what it actually
has.

The second block compares that against the seven privileges of the built-in
`PVEAuditor` role. Anything missing is named, because the reads behind it will
come back empty rather than refused, and empty is indistinguishable from clean.

The third block is the three privileges beyond the auditor role that unlock
something this CLI would use, each with the reason it is not in the recommended
role. See [Token](Token).

## When it says nothing is granted

```
  ! this token holds no privilege anywhere; every read will be empty or refused
```

Almost always privilege separation: the token was created with `--privsep 1`
and never given its own ACL entry. [Token](Token) has both fixes.
