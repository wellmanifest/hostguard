# NOTIFY

## Purpose

Declare how the implementing product informs the **founder** about a
finding or a granted block. This pack does not send notifications.

## Syntax

```text
NOTIFY
  AUDIENCE founder
  CHANNEL browser-push
  CHANNEL desktop
  PAYLOAD wellmanifest.hostguard/founder-notify/v1
```

## Inputs

- a validated hostguard finding;
- an explicit `notify_founder` action or a granted block;
- one or more configured delivery channels;
- a payload conforming to `wellmanifest.hostguard/founder-notify/v1`.

## Outputs

The implementing product emits a founder-scoped notification attempt and a
secret-free receipt. This domain pack defines the shape; it does not deliver
the notification or append an event stream.

## Errors

- `HG-NOTIFY-001` — the audience, channel, payload, or receipt is invalid.
- Missing private delivery credentials must produce a stubbed local receipt,
  not an invented secret and not an unreported success.

## Examples

```json
{
  "channel": "desktop",
  "audience": "founder",
  "policyId": "hostguard.dev-machine",
  "occurredAt": "2026-08-16T20:00:00Z",
  "scope": "host",
  "kind": "unknown_binary",
  "action": "notify_founder",
  "blocked": false,
  "body": "Unknown unused process observed; in-use tools were skipped."
}
```

## Payload shape

Canonical JSON: `schemas/hostguard-founder-notify.schema.json`.

| Field | Meaning |
| --- | --- |
| `channel` | `browser-push` or `desktop` |
| `audience` | `founder` only — not every operator |
| `policyId` | Policy document id |
| `occurredAt` | UTC timestamp |
| `scope` | `host` / `container` / `docker-engine` |
| `kind` | Finding kind |
| `action` | observe / warn / ticket / notify_founder / block |
| `blocked` | Whether a granted block was applied |
| `body` | What was found or blocked, why (kind), and that unused unknown processes were targeted while in-use tools were skipped |

## Receipts

The product emits `wellmanifest.logs/event/v1` (`eventType` such as
`hostguard.founder.notified`) and optional `poa.receipt/v1`. This pack
does not append streams.

## Secrets

VAPID private keys and push subscriptions are **not** policy fields.
If keys are absent, the product stubs `browser-push`: write a receipt
and a local event the UI can poll. Do not invent secrets.
