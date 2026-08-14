# HG-SCOPE-001

## Meaning

`probe.scopes` or a classification `scope` uses a value other than
`host`, `container`, or `docker-engine`.

## Cause

A typo, a competing vocabulary, or a missing scopes list.

## Resolution

Use only those three scopes. Docker engine findings (docker.sock,
privileged, host PID namespace) are in-scope on a **developer** host.
The pack still does not probe; the product names the scope on each finding.
