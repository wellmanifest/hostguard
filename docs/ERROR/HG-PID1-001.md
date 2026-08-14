# HG-PID1-001

## Meaning

`kill.never` is missing `pid:1`, `guardian_self`, or `allowlisted_instance`.

## Cause

A policy omitted the protected set, or treated PID 1 / the guardian as a
normal process.

## Resolution

Always list `pid:1`, `guardian_self`, and `allowlisted_instance` under
`kill.never`. The product must refuse those PIDs even when kill is granted.
