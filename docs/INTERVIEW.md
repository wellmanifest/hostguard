# INTERVIEW

## Purpose

Ask the questions that classify host signals before any warn, ticket, or kill
policy is written.

## Syntax

```bash
PYTHONPATH=src python3 -m hostguard interview --answers examples/linux-host.interview.json
PYTHONPATH=src python3 -m hostguard questions
```

## Inputs

Interactive stdin answers, or a JSON document conforming to
`schemas/hostguard-interview.schema.json`. The catalog is
`questions/interview.json`.

## Outputs

A canonical `wellmanifest.hostguard/policy/v1` document (`--format json`) or
its text projection (`--format dsl`).

## Errors

Invalid answers fail with `HG-KIND-001`, `HG-INTERVAL-001`, or `HG-SERVE-001`.
`probe_source=editor-view` is rejected.

## Examples

```bash
PYTHONPATH=src python3 -m hostguard interview --answers examples/probe-noise.interview.json --format dsl
```

That interview must emit `KIND probe_noise` and a clarifying `QUESTION`.
