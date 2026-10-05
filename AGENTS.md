# AGENTS.md

This repository is the generic host-threat **policy** layer for Wellmanifest.
Use it when a user asks how to classify CPU/RAM/storage/power pressure or
security holes (suspicious process, Docker, listeners) before warning,
ticketing, notifying the founder, or blocking. It is not the host agent
and not guard-agent.

## Before changing anything

1. Do **not** add a probe loop, systemd unit, `os.kill`, or a live blocker here.
2. Resource runtime belongs in `subactor/hostguard`. Security+notify runtime
   belongs in `subactor/guard-agent`.
3. Run the interview, or fill `wellmanifest.hostguard/interview/v1` answers.
4. Classify. Read `KIND` and `QUESTION`.
5. This pack is propose-only: it never authorizes a kill or a block.

```bash
PYTHONPATH=src python3 -m hostguard questions
PYTHONPATH=src python3 -m hostguard validate examples/linux-host.hostguard.json
PYTHONPATH=src python3 -m hostguard validate examples/linux-dev-docker.hostguard.json
```

## Classification rules you must not invert

- High `top` number → `inventory_vs_runtime`. **Do not treat top as a threat.**
- In-use tools (Cursor, shells, dockerd) → inventory. **Do not treat in-use as a threat.**
- Editor buffer vs live host → `served_artifact`. **Do not treat source as host.**
- Visible Kill/Block vs grant → `capability_surface`. **Do not treat chrome as a grant.**
- Analyzer/`top` noise → `probe_noise`. **Do not treat noise as debt.**
- PID 1, guardian, allowlisted instance, in-use tool → never kill/block.
- `unknownPolicy` must stay `reject`.
- Any product claiming this standard MUST satisfy `docs/RESILIENCE.md`
  (`RES-001`..`RES-011`): storage floor, ENOSPC as degraded state, sockets
  outside `/tmp`, liveness by endpoint ping not PID, bounded readiness wait,
  `doctor` and `--no-daemon`. Do not weaken a default or drop a proof test.
- Notify audience is **founder**, not every operator.
- `dockerSock` default is `none`. RW is invalid.

## Relation to wellmanifest/dsl

Canonical documents are JSON AST. `DOCUMENT HOSTGUARD` is a projection.
The pack manifest is `dsl-manifest.json` (`wellmanifest.hostguard`).

If `wellmanifest/dsl` is available locally:

```bash
python3 /path/to/dsl/src/dsl_check.py validate dsl-manifest.json
```

Digest-bind artifacts after you change a normative file.

## Relation to other Wellmanifest repos

- `poa` owns grants. Kill is `capability://hostguard/kill/v1`. Block is
  `capability://hostguard/block/v1`.
- `logs` owns event/receipt shape. The product emits those; this pack does not append streams.
- `new-project` governance is not adopted in this bootstrap. Keep the pack small.
  Do not copy `.governance/` here unless a later ticket says so.

## Working in this repository

- Keep executable source in `src/` and tests in `tests/`.
- Example documents are generic Linux host method illustrations.
- Run `PYTHONPATH=src python3 -m unittest discover -s tests` before claiming
  the classifier changed.

English is the working language. A short Polish intro in `README.md` is
intentional.
