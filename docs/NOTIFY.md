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

- a validated `wellmanifest.hostguard/policy/v1` document;
- a typed finding and its policy scope;
- an explicit founder-notification channel selected by the implementing
  product;
- optional POA receipt metadata when a separately granted block occurred.

No VAPID key, subscription secret or delivery credential is accepted by this
DSL document.

## Outputs

The pack proposes a closed
`wellmanifest.hostguard/founder-notify/v1` JSON document. A product may map
that inert proposal to a notification and emits its own logs/POA receipt. The
pack itself sends nothing.

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

## Errors

- `HG-NOTIFY-001`: audience is not `founder`, no channel is selected, or an
  unknown channel/payload schema is supplied;
- `HG-SCOPE-001`: the finding and notification scopes are incompatible;
- unresolved credentials are a product-runtime failure and MUST NOT be copied
  into the policy or notification proposal.

## Examples

```text
NOTIFY
  AUDIENCE founder
  CHANNEL desktop
  PAYLOAD wellmanifest.hostguard/founder-notify/v1
```

This example is a proposal only; it is not a command to a desktop service.
