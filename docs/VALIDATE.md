# VALIDATE

## Purpose

Fail closed on an invalid interview or policy document.

## Syntax

```bash
PYTHONPATH=src python3 -m hostguard validate examples/linux-host.hostguard.json
PYTHONPATH=src python3 -m hostguard validate examples/invalid/missing-interval.hostguard.json --format json
```

## Inputs

A JSON or `DOCUMENT HOSTGUARD` text file.

## Outputs

`ok` or a list of findings. `--format json` emits
`wellmanifest.hostguard/check-result/v1`.

## Errors

| Code | When |
| --- | --- |
| `HG-KIND-001` | unknown schema, kind, action, or signal |
| `HG-INTERVAL-001` | missing or too-small `probe.intervalSeconds` |
| `HG-UNKNOWN-001` | `unknownPolicy` is not `reject` |
| `HG-GRANT-001` | kill granted without the hostguard capability, or missing `kill_without_grant` |
| `HG-PID1-001` | `kill.never` missing PID 1 / guardian / allowlist |
| `HG-CLASSIFY-001` | missing `inventory_vs_runtime` or `treat_top_as_threat` forbid |
| `HG-POA-001` | missing `capability_surface` or `treat_visible_kill_as_grant` forbid |
| `HG-SERVE-001` | editor-view source, or missing `treat_editor_as_host` forbid |
| `HG-NOISE-001` | probe noise treated as debt |
| `HG-BLOCK-001` | block granted without hostguard capability, or chrome treated as block grant |
| `HG-NOTIFY-001` | notify audience is not founder, or unknown channel |
| `HG-SCOPE-001` | unknown probe/classification scope |
| `HG-INUSE-001` | in-use tools treated as threats |
| `HG-DOCKER-001` | docker.sock RW default / invalid dockerSock |

## Examples

`examples/invalid/unknown-policy-preserve.hostguard.json` must fail with
`HG-UNKNOWN-001`. `examples/invalid/block-without-grant.hostguard.json`
must fail with `HG-BLOCK-001`.
