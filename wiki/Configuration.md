# Configuration

## The file

One file, `$HOME/.mlab/proxmox.conf`, JSON, holding any number of named
profiles plus the name of the default one. It is written 0600 inside a 0700
directory because it contains a token secret, and mlab-proxmox warns on every
run if the permissions have drifted.

```json
{
  "default": "lab",
  "profiles": {
    "lab": {
      "host": "10.0.10.11",
      "token_id": "mlab@pve!audit",
      "token_secret": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "fingerprint": "A1:B2:C3:D4:E5:F6:07:18:…",
      "insecure": true
    }
  }
}
```

A profile is a **cluster**, not a node: `pveproxy` forwards a request for
another node's path to whichever node owns it, so one host and one token reach
everything.

| Field | Meaning |
| --- | --- |
| `host` | Any node: hostname, IP, or `host:port`. |
| `port` | When the host carries none. Defaults to 8006. |
| `token_id` | `user@realm!tokenname`. |
| `token_secret` | The UUID shown once at creation. |
| `fingerprint` | The certificate seen at `login`, recorded so a change can be reported. |
| `insecure` | Skip certificate verification. Defaults to true, see [Install](Install). |
| `output` | `human` or `json` for this profile. |

## Managing profiles

```bash
mlab-proxmox login --name lab --host 10.0.10.11 --token-id 'mlab@pve!audit'
mlab-proxmox profile list
mlab-proxmox profile show lab
mlab-proxmox profile use lab
mlab-proxmox profile remove old
mlab-proxmox config path
mlab-proxmox config show
```

`profile show` and `config show` mask the secret down to its last four
characters. Nothing else in the CLI ever prints it.

```
  ● lab  10.0.10.11:8006  mlab@pve!audit  tls off

  ● default profile
```

## Precedence

Flags override environment variables, which override the profile.

```
  --host / --token-id / --token-secret / --port / --insecure / --secure / --output
  MLAB_PROXMOX_HOST   then   PROXMOX_HOST   then   PVE_HOST
  the profile in proxmox.conf
```

Every setting takes all three prefixes, so `PROXMOX_TOKEN_SECRET`,
`PVE_TOKEN_SECRET` and `MLAB_PROXMOX_TOKEN_SECRET` are all read, in that order
of increasing precedence. The variables are `HOST`, `PORT`, `TOKEN_ID`,
`TOKEN_SECRET`, `INSECURE` and `OUTPUT`.

With a secret in the environment, no config file is needed at all:

```bash
export PROXMOX_HOST=10.0.10.11
export PROXMOX_TOKEN_ID='mlab@pve!audit'
export PROXMOX_TOKEN_SECRET=3fa85f64-5717-4562-b3fc-2c963f66afa6
mlab-proxmox ping
```

Prefer that to `--token-secret` on a command line, which is visible to every
other user of the machine in `ps`.

`MLAB_CONFIG_DIR` moves the whole directory, which is what the tests use.

## Global flags

| Flag | Effect |
| --- | --- |
| `-p, --profile NAME` | Use this profile rather than the default. |
| `-o, --output human\|json` | See [Output](Output). |
| `-q, --quiet` | Silence progress and status lines on stderr. |
| `--timeout SECS` | Per-request timeout, 30 by default. |
| `--insecure` / `--secure` | Two flags for one tri-state, so a profile's setting can be turned off from the command line. |
