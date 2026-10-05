# RESILIENCE

## Purpose

A conformance standard for any program (CLI, daemon, agent, IDE helper) that
claims the hostguard standard. It encodes the failure class "disk full →
stale daemon → dead control socket → client waits forever" so it cannot
regress. This pack stays **propose-only**: these are rules a product must
satisfy and a test must prove. The pack ships no probe, watcher, or killer.

## Incident that motivated it

A managed daemon (`codex app-server --managed-daemon`) kept running for days
after its Unix socket under `/tmp/<app>-daemon-<uid>/` was removed
(`systemd-tmpfiles-clean`, disk pressure). `daemon.pid` still named a live
PID, so every new client waited for a socket that could never reappear and
failed with "app server did not become ready". Root filesystem had hit 100%
(`ENOSPC`), SQLite/rollout writes failed, and an orphan child held a lock for
two days.

## Rules

Each rule has an id, a MUST, and the test that proves it.

| Id | MUST | Proof |
| --- | --- | --- |
| `RES-001` storage floor | Before any write-heavy start (new session, migration, rollout, DB open) check free bytes **and** free inodes on the target filesystem. Below the floor (default: 5% or 2 GiB, whichever is larger) refuse new work, keep serving reads, emit a founder notification. Never half-write. | Test with a size-limited tmpfs: start is refused with a typed error, existing data unchanged. |
| `RES-002` ENOSPC is a state, not a crash | `ENOSPC`/`EDQUOT` moves the process to `degraded:storage-full`. Buffered writes are retried with backoff and bounded memory; on bound exhaustion the product stops accepting writes and says so. It must not loop-log into the full disk. | Inject ENOSPC on write; assert state change, bounded buffer, bounded log rate. |
| `RES-003` socket durability | Control sockets and PID files live in a directory the product owns and `tmpfiles.d`/tmp cleaners do not touch (`$XDG_RUNTIME_DIR/<app>/`, mode 0700), never bare `/tmp`. | Test: runtime dir is outside `/tmp`; a `tmpfiles --clean` simulation leaves the socket. |
| `RES-004` self-heal a missing socket | A daemon verifies its own socket path (`stat` + inode match) on an interval ≤ 60 s. If the node is gone, it re-binds; if it cannot, it exits non-zero so its supervisor restarts it. A live process with no reachable endpoint is invalid. | Unlink the socket under a running daemon; assert re-bind or exit within the interval. |
| `RES-005` liveness is reachability, not PID | A client decides "daemon is up" by a protocol ping over the endpoint, never by `kill -0 <pid>` or a PID file alone. PID reuse is guarded by start-time identity. | Test: PID alive + socket gone → client reports `stale-daemon`, not "ready". |
| `RES-006` bounded wait, typed failure | Readiness waits have a deadline (default 10 s) and fail with a typed reason (`stale-daemon`, `storage-full`, `lock-held`). The message names the fix command. | Assert error code and hint text. |
| `RES-007` auto-recover stale daemon | On `stale-daemon` the client may (a) verify the PID is ours via start-time + executable identity, (b) send graceful stop, (c) wait, (d) only then SIGKILL, (e) remove the dead socket, (f) start fresh. It must never kill a PID it cannot identify. A `--no-daemon` escape hatch MUST exist. | Test with a fake daemon process; unidentified PID is left alone. |
| `RES-008` child lifecycle | Every spawned child has a deadline or heartbeat and a process group; parent exit or timeout reaps the group. Lock holders older than their TTL are reported, not silently waited on. | Spawn a child that holds a lock; assert it is reaped or reported after TTL. |
| `RES-009` log and state caps | Logs, history DBs, caches have size caps with rotation/compaction (a 2.5 GB history file is a finding). Caps are in config, with defaults. | Test: writes past cap rotate; total footprint stays under cap. |
| `RES-010` multi-install precedence | If several executables of the same product are on `PATH`, the product (or `doctor`) reports the shadowed ones and versions. | `doctor` output lists all resolved binaries. |
| `RES-011` doctor command | `doctor` checks RES-001, 003, 004, 005, 009, 010 offline, exits non-zero on any failure, and prints the exact repair command. | Run against a fixture home with each fault injected. |

## Escalation

Findings follow the pack's effect model: observe → warn → ticket →
notify_founder → escalate. `RES-001`/`RES-002` default to `notify_founder`.
Kill of a stale daemon (`RES-007`) is `capability://hostguard/kill/v1` and
needs a grant when done by an agent; a user running their own client may
recover their own daemon.

## Errors

- `HG-RES-001` — a product claims hostguard but lacks proof for a rule above.

## Regression guard

Adopting repos add the table above as a conformance test suite. A change that
removes a proof test, or lowers a default (floor, deadline, cap) without a
ticket, fails review. Fault-injection fixtures (tmpfs, unlinked socket, fake
daemon PID) are the regression anchors; the incident above is the named
regression case `incident-stale-socket-enospc`.

## Adoption at any scale

A product claims this standard with one file, `resilience.conformance.json`
(`wellmanifest.hostguard/resilience/v1`, schema
`schemas/hostguard-resilience.schema.json`, example
`examples/resilience.conformance.json`). Each `RES-*` rule is either
`proven` (names the product's fault-injection test) or `waived` (names a
ticket and a reason). `scope` (`cli`, `daemon`, `agent`, `fleet`) says which
rules apply; a CLI with no daemon waives `RES-003`..`RES-007` explicitly
rather than silently. The same file works for one script or a fleet of
agents: a fleet runner reads every product's declaration and reports the
unproven or waived rules, with no per-product special cases.

Defaults in the declaration may only be stricter than the standard
(floor ≥ 5% / 2 GiB, readiness ≤ 10 s, socket check ≤ 60 s).

## Where code lives

This pack and its schema are standard only. Executable code is written in
concrete products and never here:

- `subactor/hostguard` — storage/inode probe, `degraded:storage-full`
  signal, conformance checker that reads `resilience.conformance.json`,
  fleet report.
- `subactor/guard-agent` — founder notification, granted stale-daemon
  recovery (`capability://hostguard/kill/v1`).
- Each product (a daemon, a CLI) — its own `doctor`, socket self-heal,
  ping liveness, and the fault-injection tests named in its declaration.

## Out of scope

No probe loop, no systemd unit, no `os.kill` in this pack. Runtime belongs in
`subactor/hostguard` and `subactor/guard-agent`.
