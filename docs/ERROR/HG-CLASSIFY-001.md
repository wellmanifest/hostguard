# HG-CLASSIFY-001

## Meaning

The policy is missing `inventory_vs_runtime`, `classify_before_threat`, or
the `treat_top_as_threat` forbid.

## Cause

A high number in `top` was treated as “this process threatens the instance.”

## Resolution

Classify allowlist, cgroup, and instance ownership first. A high CPU in
`top` is inventory until that interview is done.
