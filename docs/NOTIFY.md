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
