# Output

Two formats, and three rules that keep them from getting in each other's way.

## The rules

**Progress goes to stderr.** stdout carries the result, so `-o json | jq` stays
parsable while a spinner is running.

**Nothing is drawn unless stderr is a terminal.** Pipes, CI logs and tests get
clean output with no escape sequences. `CI=1` has the same effect.

**Nothing is drawn for fast work.** The spinner only appears once a call has
run past 250ms, because the flash of one appearing and vanishing reads as a
glitch rather than as feedback.

## Human

The default. Two-space indent, dimmed labels, one blank line around each block,
and numbers rendered the way they are meant rather than the way they arrive:

```
  NAME           VMID  NODE    TYPE  STATUS   UPTIME   MAXDISK    MAXMEM
  web01       150   pve1  qemu  running  12d 04h  50.0 GiB   8.0 GiB
```

`uptime` is seconds in the API, `maxdisk` is bytes, `cpu` is a load fraction
where 1.0 means one core saturated. A column drops out entirely when no row
fills it, so the width follows what the cluster actually has.

## JSON

```bash
mlab-proxmox audit -o json
mlab-proxmox guests list -o json | jq '.[] | select(.status=="running") | .name'
```

Raw, untouched, exactly what the API returned or exactly what the checks
produced — nothing is humanised there. A graded command emits one object:

```json
{
  "title": "Audit of lab (https://10.0.10.11:8006/api2/json)",
  "summary": { "critical": 0, "high": 4, "medium": 1, "low": 6, "info": 14,
               "unreadable": 2, "worst": "high" },
  "findings": [
    {
      "id": "firewall.cluster-disabled",
      "severity": "high",
      "subject": "cluster",
      "title": "the cluster firewall is off",
      "detail": "…",
      "remedy": "…"
    }
  ],
  "unreadable": [
    { "path": "/nodes/pve1/apt/update", "reason": "API error 403: …" }
  ]
}
```

The `unreadable` list is part of the contract: a check that could not run is
not a check that passed. See [Checks](Checks).

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The command ran. Findings are not failures. |
| 1 | The command failed: no profile, no connection, a refused credential. |
| 2 | `audit --fail-on LEVEL` and a finding at that level or worse exists. |

```bash
mlab-proxmox audit --fail-on high || echo "something needs attention"
```
