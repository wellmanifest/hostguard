# HG-BLOCK-001

## Meaning

Block is granted without `capability://hostguard/block/v1`, uses a foreign
capability, omits `block_without_grant`, or treats a visible Block control
as a POA grant.

## Cause

A document treated a desired stop, a UI control, or another capability URI
as authority to block a process or container.

## Resolution

Default `block.granted` to false. Require the exact hostguard block
capability. Keep `block_without_grant` and `treat_visible_block_as_grant`
in `policy.forbid` when a `policy.block` section is present. The product
still needs an explicit grant file before it may apply a block. Default
effect is observe+ticket+notify_founder.
