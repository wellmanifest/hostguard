# Mapping

How this pack sits on sibling Wellmanifest standards and the subactor product.

| Standard | Relation | What hostguard reuses |
| --- | --- | --- |
| `wellmanifest/dsl` | implements | JSON AST canonical, text projection, `dsl-manifest.json`, `unknownPolicy=reject` |
| `wellmanifest/logs` | compatible-with | Product cycles emit `wellmanifest.logs/event/v1` (`mode=PLAN` for check, `receiptRef` when a granted kill/block or founder notify is applied). This pack does not append streams. Notify payload: `wellmanifest.hostguard/founder-notify/v1`. |
| `wellmanifest/poa` | compatible-with | Kill is `capability://hostguard/kill/v1`. Block is `capability://hostguard/block/v1`. A document is not a grant. Receipts follow `poa.receipt/v1` in the product. |
| `wellmanifest/new-project` | optional later | Same bootstrap as `wellmanifest/ssot`: keep the pack small; do not copy `.governance/` until a ticket says so. Tickets for the *product* are planfile records in `subactor/hostguard` / `subactor/guard-agent`, not GitHub PRs. |
| `subactor/hostguard` | implemented-by | Cyclic resource probe, warn, planfile tickets, optional granted kill. Never PID 1, never self. |
| `subactor/guard-agent` | implemented-by | Security holes, in-use skip, founder notify (desktop + browser-push stub), optional granted block. May call hostguard libraries. No daemon in this pack. |

Effect split:

- Pack: propose-only documents (`classify` / `suggest` / `validate`).
- Product: observe is default; notify is declared; kill/block are granted and receipted.
