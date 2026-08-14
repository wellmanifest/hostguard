# HOSTGUARD

## Purpose

Declare how a host should classify process resource signals and security
holes before warn, ticket, founder notify, or a granted kill/block. The
document does not probe a machine.

## Syntax

Canonical form is UTF-8 JSON conforming to
`schemas/hostguard-policy.schema.json`. The text projection starts with
`DOCUMENT HOSTGUARD` and is emitted by `hostguard suggest`.

```text
DOCUMENT HOSTGUARD
ID <identifier>
VERSION <semver>
SCHEMA wellmanifest.hostguard/policy/v1
PROBE
  INTERVAL <seconds>
  SOURCE live-host|injected-snapshot
  SCOPE host|container|docker-engine
  DOCKER_SOCK none|read-only
  SIGNAL cpu|ram|storage|power|fd|inode|zombie|fork_bomb|runaway|listener|docker_sock|docker_privileged|cap_escalation|unknown_binary|crypto_miner
POLICY observe-default
  UNKNOWN reject
  DEFAULT observe
  KILL granted=false capability=capability://hostguard/kill/v1
  BLOCK granted=false capability=capability://hostguard/block/v1
  NEVER pid:1
NOTIFY
  AUDIENCE founder
  CHANNEL browser-push
  CHANNEL desktop
CLASSIFY <identifier>
  KIND inventory_vs_runtime|suspicious_process|docker_privileged|...
  SCOPE host|container|docker-engine
```

## Inputs

A policy document or typed interview answers. `top` output is evidence, not
a classification. In-use tools are inventory until the interview says
otherwise.

## Outputs

A propose-only hostguard policy document and optional text DSL projection.

## Errors

See `docs/ERROR/` for `HG-KIND-001`, `HG-GRANT-001`, `HG-PID1-001`,
`HG-INTERVAL-001`, `HG-CLASSIFY-001`, `HG-POA-001`, `HG-SERVE-001`,
`HG-NOISE-001`, `HG-UNKNOWN-001`, `HG-BLOCK-001`, `HG-NOTIFY-001`,
`HG-SCOPE-001`, `HG-INUSE-001`, and `HG-DOCKER-001`. Killing without a
grant is `docs/CRITICAL/HG-KILL-001.md`. Blocking without a grant is
`docs/CRITICAL/HG-BLOCK-001.md`.

## Examples

`examples/linux-host.hostguard.json` encodes observe-default, reject unknown,
founder notify, and ungranted block. `examples/linux-dev-docker.hostguard.json`
adds Docker and security kinds. Products: `subactor/hostguard` (resources)
and `subactor/guard-agent` (holes + notify).
