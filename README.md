# wellmanifest/hostguard

Warstwa do opisu zagrożeń procesami na hoście: najpierw klasyfikacja, potem
dokument polityki. To **wzorzec**, nie agent.

A generic host-threat policy pack. It interviews, classifies, and emits a
propose-only DSL document. It does not probe `/proc`, start a daemon, or kill
a process. The implementing product is [`subactor/hostguard`](https://github.com/subactor/hostguard).

This repository is a **domain pack** on [`wellmanifest/dsl`](https://github.com/wellmanifest/dsl).
Canonical documents are JSON AST (`wellmanifest.hostguard/policy/v1`).
`DOCUMENT HOSTGUARD` is a projection.

## Why this exists

`top` showing high CPU is not “this process threatens the instance.” Dual
truths (inventory vs the live host), chrome vs grant, and analyzer noise must
be classified before warn, ticket, or kill. Kill is a separate
`capability://hostguard/kill/v1` with `unknownPolicy=reject`.

Lessons encoded here (method, not product code):

1. `inventory_vs_runtime` — a high number in `top` is not a threat until
   classified (allowlist, cgroup, our service).
2. `served_artifact` — the product must probe the live host, not the editor.
3. `capability_surface` — a visible Kill button is not a POA grant.
4. Do not treat analyzer or `top` noise as debt.

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
observe → warn → ticket → escalate. Kill is declared, not executed here.

## CLI (documents only)

```bash
PYTHONPATH=src python3 -m hostguard questions
PYTHONPATH=src python3 -m hostguard classify examples/linux-host.interview.json
PYTHONPATH=src python3 -m hostguard suggest examples/linux-host.hostguard.json
PYTHONPATH=src python3 -m hostguard validate examples/linux-host.hostguard.json
PYTHONPATH=src python3 -m unittest discover -s tests
```

There is no `probe`, `watch`, or `kill` command in this pack.

## Kinds

| Kind | Meaning | Default next action |
| --- | --- | --- |
| `inventory_vs_runtime` | `top` ≠ threat | Classify before warn |
| `served_artifact` | Editor ≠ host | Product probes live host |
| `capability_surface` | Chrome ≠ grant | Require kill grant |
| `allowlisted_instance` | Our service | Never kill |
| `guardian_self` | The product itself | Never kill |
| `init_pid` | PID 1 | Never kill |
| `runaway_process` | Classified foreign threat | Ticket; propose kill only if granted |
| `resource_pressure` | Host-level cpu/ram/disk/power | Ticket |
| `fork_bomb` / `zombie_storm` | Process table threat | Ticket |
| `probe_noise` | Analyzer/`top` noise | Ask; not debt |
| `unknown_process` | Unclassified | reject |

## Signals

`cpu`, `ram`, `storage`, `power`, `fd`, `inode`, `zombie`, `fork_bomb`, `runaway`.
Interval lives in the document (`probe.intervalSeconds`), not in pack code.

## Related

- [`wellmanifest/dsl`](https://github.com/wellmanifest/dsl) — kernel
- [`wellmanifest/logs`](https://github.com/wellmanifest/logs) — event/receipt shape the product emits
- [`wellmanifest/poa`](https://github.com/wellmanifest/poa) — grant / `unknownPolicy=reject`
- [`wellmanifest/new-project`](https://github.com/wellmanifest/new-project) — optional later governance
- [`subactor/hostguard`](https://github.com/subactor/hostguard) — cyclic probe, tickets, granted kill
