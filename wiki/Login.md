# `mlab-proxmox login`

Create or update a profile, prove the token works, and save it.

```bash
mlab-proxmox login --name lab --host 10.0.10.11 --token-id 'mlab@pve!audit'
```

```
  ✔ connected to Proxmox VE 9.1.1
  › node pve1, 1 node(s) in the cluster
  › the token holds privileges on 8 path(s), 8 of them at /
  ! TLS certificate verification is off for this profile
  ✔ saved profile "lab" to /Users/you/.mlab/proxmox.conf
```

It prompts for the token secret without echoing it. Anything you do not pass on
the command line and that the profile already has is kept — re-running `login`
on an existing profile to change only the host does not ask for the secret
again.

## What it checks before writing

- `/version`, so a wrong host or a wrong port fails here rather than later.
- `/cluster/status`, which names the node that answered.
- That node's certificate fingerprint, recorded in the profile. A later `login`
  that sees a different one says so — which is the part that detects an
  interception, rather than the part that silently accepts one.
- `/access/permissions`, so the token's reach is reported at setup time. A
  token with nothing at `/` gets a warning immediately.

## Flags

| Flag | Effect |
| --- | --- |
| `-n, --name NAME` | Profile to create or update. Defaults to `default`. |
| `--set-default` | Make it the default profile. The first profile always becomes it. |
| `--no-test` | Save without checking. For a cluster that is currently down. |
| `--non-interactive` | Never prompt; fail when something is missing. |

For scripted setup, keep the secret out of the command line:

```bash
PROXMOX_TOKEN_SECRET=… mlab-proxmox login --name lab --host 10.0.10.11 \
  --token-id 'mlab@pve!audit' --non-interactive
```

The file is written 0600 in a 0700 directory. See [Configuration](Configuration).
