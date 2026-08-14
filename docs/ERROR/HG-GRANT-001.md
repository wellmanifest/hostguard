# HG-GRANT-001

## Meaning

Kill is granted without `capability://hostguard/kill/v1`, uses a foreign
capability, or the policy is missing `kill_without_grant`.

## Cause

A document treated a desired kill, a UI control, or another capability URI
as authority.

## Resolution

Default `kill.granted` to false. Require the exact hostguard capability.
Keep `kill_without_grant` in `policy.forbid`. The product still needs an
explicit grant before it may apply a kill.
