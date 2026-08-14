# HG-BLOCK-001

## Risk

A block (process stop, container kill/stop, drop-cap) runs without
`capability://hostguard/block/v1`, or targets PID 1, the guardian, an
allowlisted instance, or a tool currently in use.

## Detection

`block.granted` is true without the hostguard block capability,
`block.never` is incomplete, or a product CLI applies block from
`check` / `probe` / `watch`. This pack must not contain a probe loop
or a live blocker.

## Remediation

Keep observe+ticket+notify as the default. Put block behind an explicit
grant in `subactor/guard-agent`. Refuse PID 1, self, allowlisted comms/
images, and in-use tools. Prefer stopping a container or dropping
capabilities over killing a host PID. Receipt the effect with
`wellmanifest.logs` / `poa.receipt/v1`.

## Verification

Pack tests contain no live block. Product tests inject a fake blocker
and assert PID 1, in-use tools, and ungranted paths never call it.
