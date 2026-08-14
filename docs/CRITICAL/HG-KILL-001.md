# HG-KILL-001

## Risk

A kill runs without `capability://hostguard/kill/v1`, or targets PID 1, the
guardian, or an allowlisted instance process.

## Detection

`kill.granted` is true without the hostguard capability, `kill.never` is
incomplete, or a product CLI applies kill from `check`/`suggest`. This pack
must not contain `os.kill` or a probe loop.

## Remediation

Keep observe+warn+ticket as the default. Put kill behind an explicit grant
in `subactor/hostguard`. Refuse PID 1, self, and allowlisted comms/cgroups.
Receipt the effect with `wellmanifest.logs` / `poa.receipt/v1`.

## Verification

Pack tests contain no live kill. Product tests inject a fake killer and
assert PID 1 and ungranted paths never call it.
