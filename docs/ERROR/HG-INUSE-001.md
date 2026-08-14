# HG-INUSE-001

## Meaning

In-use tools were treated as threats, or `treat_in_use_tool_as_threat`
is missing from `inventory_vs_runtime` / `policy.forbid`.

## Cause

A running editor, shell, Docker engine, or instance service was classified
as suspicious because it appeared in `ps` / `docker ps`.

## Resolution

Allowlist processes, images, and tools **in use**. They are inventory
until interview/policy says otherwise (same lesson as `inventory_vs_runtime`
and chrome-vs-grant). Unknown unused binaries, especially in containers,
still fail closed.
