# Mapping

How this pack sits on sibling Wellmanifest standards and the subactor product.

| Standard | Relation | What hostguard reuses |
| --- | --- | --- |
| `wellmanifest/dsl` | implements | JSON AST canonical, text projection, `dsl-manifest.json`, `unknownPolicy=reject` |
| `wellmanifest/logs` | compatible-with | Product cycles emit `wellmanifest.logs/event/v1` (`mode=PLAN` for check, `receiptRef` when a granted kill is applied). This pack does not append streams. |
| `wellmanifest/poa` | compatible-with | Kill is `capability://hostguard/kill/v1`. A document is not a grant. Receipts follow `poa.receipt/v1` in the product. |
| `wellmanifest/new-project` | optional later | Same bootstrap as `wellmanifest/ssot`: keep the pack small; do not copy `.governance/` until a ticket says so. Tickets for the *product* are planfile records in `subactor/hostguard`, not GitHub PRs. |
| `subactor/hostguard` | implemented-by | Cyclic probe, warn, planfile tickets, optional granted kill. Never PID 1, never self. |

Effect split:

- Pack: propose-only documents (`classify` / `suggest` / `validate`).
- Product: observe is default; kill is granted and receipted.
