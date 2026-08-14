# HG-SERVE-001

## Meaning

`probe.source` is `editor-view`, or `served_artifact` does not forbid
`treat_editor_as_host`.

## Cause

An editor buffer or a source tree was treated as the live host.

## Resolution

The product probes `/proc` on the served machine, or accepts an injected
snapshot taken from that host. `editor-view` is rejected.
