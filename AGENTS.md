# AGENTS.md

This repository is the generic host-threat **policy** layer for Wellmanifest.
Use it when a user asks how to classify CPU/RAM/storage/power pressure before
warning, ticketing, or killing. It is not the host agent.

## Before changing anything

1. Do **not** add a probe loop, systemd unit, or `os.kill` here.
2. Runtime belongs in `subactor/hostguard`.
3. Run the interview, or fill `wellmanifest.hostguard/interview/v1` answers.
4. Classify. Read `KIND` and `QUESTION`.
5. This pack is propose-only: it never authorizes a kill.

```bash
PYTHONPATH=src python3 -m hostguard questions
PYTHONPATH=src python3 -m hostguard validate examples/linux-host.hostguard.json
```

## Classification rules you must not invert

- High `top` number → `inventory_vs_runtime`. **Do not treat top as a threat.**
- Editor buffer vs live host → `served_artifact`. **Do not treat source as host.**
- Visible Kill vs grant → `capability_surface`. **Do not treat chrome as a grant.**
- Analyzer/`top` noise → `probe_noise`. **Do not treat noise as debt.**
- PID 1, guardian, allowlisted instance → never kill.
- `unknownPolicy` must stay `reject`.

## Relation to wellmanifest/dsl

Canonical documents are JSON AST. `DOCUMENT HOSTGUARD` is a projection.
The pack manifest is `dsl-manifest.json` (`wellmanifest.hostguard`).

If `wellmanifest/dsl` is available locally:

```bash
python3 /path/to/dsl/src/dsl_check.py validate dsl-manifest.json
```

Digest-bind artifacts after you change a normative file.

## Relation to other Wellmanifest repos

- `poa` owns grants. Kill is `capability://hostguard/kill/v1`.
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
