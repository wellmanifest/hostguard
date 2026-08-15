# RAPL

## Purpose

Document how a hostguard **product** may fill `host.powerWatts` from Intel/AMD
RAPL. This pack does **not** probe `/sys/class/powercap`. There is no RAPL
reader, sleeper, or live two-sample loop here.

## Syntax

```text
RAPL
  ZONE intel-rapl:N | amd-rapl:N
  SAMPLE energy_uj
  ELAPSED 0.1
  POWER_WATTS (second - first) / elapsed / 1e6
```

Package zones only. Ignore RAPL subdomains (`intel-rapl:0:0`) and MMIO
duplicates (`intel-rapl-mmio:*`).

## Inputs

A documented pair of package `energy_uj` readings, elapsed seconds, and
optional `max_energy_range_uj` for counter wrap. Not a live sysfs path.

## Outputs

`powerWatts` as a non-negative number, or `null` when the energy tree is
absent. Crossing `thresholds.powerWatts` is host `resource_pressure` →
ticket. Never kill.

## Errors

This pack has no RAPL diagnostic code. A missing sysfs tree is
`powerWatts: null`, not a finding. Live read errors belong to
`subactor/hostguard` and stay observe-only.

## Examples

`examples/fixtures/rapl-two-sample.json`:

| Field | Value |
| --- | --- |
| `firstEnergyUj` | 10000000 |
| `secondEnergyUj` | 12000000 |
| `elapsedSeconds` | 0.1 |
| `powerWatts` | 20.0 |

Runtime: [`subactor/hostguard`](https://github.com/subactor/hostguard) `hostguard.rapl`.
