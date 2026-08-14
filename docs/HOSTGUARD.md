# HOSTGUARD

## Purpose

Declare how a host should classify process resource signals before warn,
ticket, or a granted kill. The document does not probe a machine.

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
  SIGNAL cpu|ram|storage|power|fd|inode|zombie|fork_bomb|runaway
POLICY observe-default
  UNKNOWN reject
  DEFAULT observe
  KILL granted=false capability=capability://hostguard/kill/v1
  NEVER pid:1
CLASSIFY <identifier>
  KIND inventory_vs_runtime|served_artifact|capability_surface|...
```

## Inputs

A policy document or typed interview answers. `top` output is evidence, not
a classification.

## Outputs

A propose-only hostguard policy document and optional text DSL projection.

## Errors

See `docs/ERROR/` for `HG-KIND-001`, `HG-GRANT-001`, `HG-PID1-001`,
`HG-INTERVAL-001`, `HG-CLASSIFY-001`, `HG-POA-001`, `HG-SERVE-001`,
`HG-NOISE-001`, and `HG-UNKNOWN-001`. Killing without a grant is
`docs/CRITICAL/HG-KILL-001.md`.

## Examples

`examples/linux-host.hostguard.json` encodes observe-default, reject unknown,
and the three required lessons. The product that runs the interval is
`subactor/hostguard`.
