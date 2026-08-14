# HG-DOCKER-001

## Meaning

`probe.dockerSock` is not `none` or `read-only`, or the policy is missing
`mount_docker_sock_rw_by_default` when a block/docker section is declared.

## Cause

A default of mounting `docker.sock` read-write into the agent or an app
container, which is itself a hole.

## Resolution

Default `dockerSock` to `none`. Prefer **host-inspect** (`docker info` /
recorded inspect JSON) on the developer system. An in-container agent
must not require a RW socket. `read-only` is an explicit policy choice
and still a risk — document it, do not default to it.
