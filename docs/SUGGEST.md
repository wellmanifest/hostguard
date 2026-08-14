# SUGGEST

## Purpose

Emit the text DSL projection of a validated policy document so agents and
humans can review the same facts without inventing a second language.

## Syntax

```bash
PYTHONPATH=src python3 -m hostguard suggest examples/linux-host.hostguard.json
```

## Inputs

A canonical JSON policy document, or a `.dsl` / `DOCUMENT HOSTGUARD` text file.

## Outputs

The line-oriented projection. Canonical JSON remains the source of truth.

## Errors

Validation failures are printed and the command exits 1. See `VALIDATE`.

## Examples

```bash
PYTHONPATH=src python3 -m hostguard suggest examples/linux-host.hostguard.json | head
```
