# HG-NOISE-001

## Meaning

`probe_noise` is missing the `treat_probe_noise_as_debt` forbid, or analyzer
output was treated as work.

## Cause

A noisy `top` line or an analyzer hit was opened as a ticket without
classification.

## Resolution

Ask which PIDs a human confirmed as foreign. Do not treat analyzer noise as
debt.
