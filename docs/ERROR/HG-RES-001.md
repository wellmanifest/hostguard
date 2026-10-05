# HG-RES-001

## Meaning

A product claims the hostguard standard but has no passing proof for one of
the `RES-*` rules in `docs/RESILIENCE.md`.

## Cause

Missing fault-injection test, a lowered default (storage floor, readiness
deadline, log cap), or a liveness check based on PID alone.

## Resolution

Add the proof named in the rule's table row. Keep sockets and PID files out
of `/tmp`, make `ENOSPC` a degraded state, ping the endpoint instead of
trusting `daemon.pid`, and ship `doctor` plus `--no-daemon`.
