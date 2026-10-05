# wellmanifest/hostguard

Warstwa do opisu zagrożeń procesami na hoście: najpierw klasyfikacja, potem
dokument polityki. To **wzorzec**, nie agent.

A generic host-threat policy pack. It interviews, classifies, and emits a
propose-only DSL document. It does not probe `/proc`, start a daemon, kill,
or block. Implementing products:

- [`subactor/hostguard`](https://github.com/subactor/hostguard) — CPU/RAM/storage/power probe
- [`subactor/guard-agent`](https://github.com/subactor/guard-agent) — security holes, founder notify, granted block

This repository is a **domain pack** on [`wellmanifest/dsl`](https://github.com/wellmanifest/dsl).
Canonical documents are JSON AST (`wellmanifest.hostguard/policy/v1`).
`DOCUMENT HOSTGUARD` is a projection.

## Why this exists

`top` showing high CPU is not “this process threatens the instance.” Dual
truths (inventory vs the live host), chrome vs grant, in-use tools vs
unknown binaries, and analyzer noise must be classified before warn, ticket,
notify, or block. Kill is `capability://hostguard/kill/v1`. Block is
`capability://hostguard/block/v1`. Both use `unknownPolicy=reject`.

Lessons encoded here (method, not product code):

1. `inventory_vs_runtime` — a high number in `top` is not a threat until
   classified (allowlist, cgroup, our service, **tools in use**).
2. `served_artifact` — the product must probe the live host, not the editor.
3. `capability_surface` — a visible Kill/Block button is not a POA grant.
4. Do not treat analyzer or `top` noise as debt.
5. Founder notify (`browser-push`, `desktop`) is the default next step after
   observe+ticket. Block is granted, never default.
6. Docker holes (`docker.sock`, privileged, host PID) are in-scope on a
   **developer** host. Default `dockerSock` is `none`, never RW.

## Interview → DSL

```text
questions/interview.json
        │  typed answers (wellmanifest.hostguard/interview/v1)
        ▼
   hostguard classify     ← deterministic, not an LLM
        │  JSON AST (wellmanifest.hostguard/policy/v1)
        ▼
   hostguard suggest      ← DOCUMENT HOSTGUARD projection
        │
        ▼
   hostguard validate     ← fail closed
```

Effect model in the document: **observe-default**. Escalation is
observe → warn → ticket → notify_founder → escalate. Kill and block are
declared, not executed here.

## CLI (documents only)

```bash
PYTHONPATH=src python3 -m hostguard questions
PYTHONPATH=src python3 -m hostguard classify examples/linux-host.interview.json
PYTHONPATH=src python3 -m hostguard suggest examples/linux-host.hostguard.json
PYTHONPATH=src python3 -m hostguard validate examples/linux-dev-docker.hostguard.json
PYTHONPATH=src python3 -m unittest discover -s tests
```

There is no `probe`, `watch`, `kill`, or `block` command in this pack.

## Kinds

| Kind | Meaning | Default next action |
| --- | --- | --- |
| `inventory_vs_runtime` | `top` ≠ threat; in-use tools ≠ threat | Classify before warn |
| `served_artifact` | Editor ≠ host | Product probes live host |
| `capability_surface` | Chrome ≠ grant | Require kill/block grant |
| `allowlisted_instance` | Our service | Never kill/block |
| `guardian_self` | The product itself | Never kill/block |
| `init_pid` | PID 1 | Never kill/block |
| `runaway_process` | Classified foreign resource threat | Ticket; propose kill only if granted |
| `resource_pressure` | Host-level cpu/ram/disk/power | Ticket |
| `fork_bomb` / `zombie_storm` | Process table threat | Ticket |
| `probe_noise` | Analyzer/`top` noise | Ask; not debt |
| `unknown_process` | Unclassified | reject |
| `suspicious_process` | Foreign process after in-use skip | Notify founder; ticket |
| `unexpected_listener` | Unexpected bind | Notify founder; ticket |
| `docker_socket_exposure` | docker.sock visible | Notify; never default RW mount |
| `docker_privileged` | Privileged container | Notify; prefer container stop if granted |
| `capability_escalation` | Host PID / extra caps | Notify |
| `unknown_binary` | Unknown exe in a container | Fail closed unless in-use |
| `crypto_miner_pattern` | Miner comm/cmdline | Notify; skip in-use tools |

## Signals

Resource: `cpu`, `ram`, `storage`, `power`, `fd`, `inode`, `zombie`,
`fork_bomb`, `runaway`.

Security: `listener`, `docker_sock`, `docker_privileged`, `cap_escalation`,
`unknown_binary`, `crypto_miner`.

Interval lives in the document (`probe.intervalSeconds`), not in pack code.
Scope is `host` | `container` | `docker-engine`.

## Related

- [`wellmanifest/dsl`](https://github.com/wellmanifest/dsl) — kernel
- [`wellmanifest/logs`](https://github.com/wellmanifest/logs) — event/receipt shape the product emits
- [`wellmanifest/poa`](https://github.com/wellmanifest/poa) — grant / `unknownPolicy=reject`
- [`wellmanifest/new-project`](https://github.com/wellmanifest/new-project) — optional later governance
- [`subactor/hostguard`](https://github.com/subactor/hostguard) — cyclic resource probe (RAPL two-sample watts live there, not here)
- [`subactor/guard-agent`](https://github.com/subactor/guard-agent) — holes, notify, granted block

Resilience conformance (disk full, stale daemon, dead socket): [`docs/RESILIENCE.md`](docs/RESILIENCE.md).

Document-only RAPL sample: [`docs/RAPL.md`](docs/RAPL.md),
`examples/fixtures/rapl-two-sample.json`. This pack does not read sysfs.
