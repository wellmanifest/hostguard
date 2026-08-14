# CLASSIFY

## Purpose

Deterministically map typed interview answers to a hostguard policy. This
command writes a document. It does not inspect a host.

## Syntax

```bash
PYTHONPATH=src python3 -m hostguard classify examples/linux-host.interview.json
PYTHONPATH=src python3 -m hostguard classify examples/linux-host.interview.json --format dsl
```

## Inputs

A valid `wellmanifest.hostguard/interview/v1` document.

## Outputs

One policy document. Required kinds:

| Condition | Kind | Default actions |
| --- | --- | --- |
| Always | `inventory_vs_runtime` | classify before threat; forbid treating top **or in-use tools** as threat |
| Always | `served_artifact` | product probes live host; forbid editor-as-host |
| Always | `capability_surface` | require kill grant (and block grant when `policy.block` is present); forbid chrome-as-grant |
| Analyzer/`top` noise | `probe_noise` | ask; not debt |
| Docker/security signals or scopes | `suspicious_process`, `unexpected_listener`, `docker_socket_exposure`, `docker_privileged`, `capability_escalation`, `unknown_binary`, `crypto_miner_pattern` | observe + notify_founder + ticket; refuse_block unless granted |

`unknownPolicy=reject` and `defaultAction=observe` are always emitted.
`kill.granted` and `block.granted` are false unless the interview says otherwise.
Notify audience is `founder`. Channels default to `browser-push` and `desktop`.

## Errors

Interview schema or interval errors: `HG-KIND-001`, `HG-INTERVAL-001`,
`HG-SERVE-001`.

## Examples

`examples/capability-surface.interview.json` keeps `kill.granted=false` even
when a Kill button is visible.
