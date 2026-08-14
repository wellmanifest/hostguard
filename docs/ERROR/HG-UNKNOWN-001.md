# HG-UNKNOWN-001

## Meaning

`policy.unknownPolicy` is not `reject`.

## Cause

An unknown kind, signal, or capability was preserved instead of failing
closed.

## Resolution

Set `unknownPolicy` to `reject`. Unknown process classes and unknown kill
capabilities are not observed-as-ok.
