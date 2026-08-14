# HG-POA-001

## Meaning

A `capability_surface` classification is missing `require_kill_grant` or
does not forbid `treat_visible_kill_as_grant`. When `policy.block` is
present, `require_block_grant` and `treat_visible_block_as_grant` are
required (`HG-BLOCK-001`).

## Cause

Visible chrome (Kill, Stop, a dashboard button) was treated as a POA grant.

## Resolution

Test observe and kill as separate capabilities. A visible control is not
authority. `unknownPolicy=reject`.
