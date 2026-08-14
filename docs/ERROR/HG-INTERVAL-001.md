# HG-INTERVAL-001

## Meaning

`probe.intervalSeconds` is missing or below 5.

## Cause

The cycle interval was left as a magic number in product code instead of
being written in the document.

## Resolution

Set `probe.intervalSeconds` to an integer >= 5 in the policy document. The
product reads that field; it must not invent a hidden default that overrides
the document.
