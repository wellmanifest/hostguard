# HG-NOTIFY-001

## Meaning

Notify audience is not `founder`, channels are empty or unknown, or the
payload schema is not `wellmanifest.hostguard/founder-notify/v1`.

## Cause

A document notified every operator, invented a channel, or mixed secrets
into the policy.

## Resolution

Audience is the founder role only. Channels are `browser-push` and/or
`desktop`. Receipts follow `wellmanifest.logs` / `poa.receipt/v1` in the
product. Without VAPID keys the product stubs browser-push (receipt +
local poll event) and must not invent secrets.
