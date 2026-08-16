# DOCKER

## Purpose

Declare Docker-related finding kinds and how policy applies to a
**developer** host and to containerized instances of the agent.

## Syntax

```text
DOCKER
  SCOPE docker-engine
  PROBE dockerSock read-only
  DEFAULT observe
```

## Inputs

- recorded engine, container, listener, and process observations;
- an explicit scope: `host`, `container`, or `docker-engine`;
- the declared `probe.dockerSock` mode;
- an optional capability grant for a blocking action.

## Outputs

The validator produces classified findings and proposed actions. It does not
open `docker.sock`, stop a container, kill a process, or mutate engine state.

## Errors

- `HG-DOCKER-001` — an unsupported Docker probe mode or unsafe socket access
  was declared.
- `HG-GRANT-001` — a blocking action lacks the required capability grant.

## Examples

```text
DOCKER
  SCOPE container
  PROBE dockerSock none
  FINDING docker_privileged
  ACTION notify_founder
```

## Scopes

| Scope | Meaning |
| --- | --- |
| `host` | Processes and listeners on the developer machine |
| `container` | A containerized workload or a containerized agent |
| `docker-engine` | Engine configuration: docker.sock, privileged, host PID |

Findings about `docker.sock`, privileged containers, and host PID
namespace are in-scope for a dev host. The pack still does not probe.

## docker.sock

`probe.dockerSock` may be `none` (default) or `read-only`.
Read-write is **not** a valid value (`HG-DOCKER-001`).

Prefer **host-inspect** from the developer system (`docker info`,
`docker events`, recorded `docker inspect` JSON) so the agent does not
need to be privileged inside every app container.

Running the agent **inside** a container is a deployment choice. The
default image must not mount docker.sock RW. A read-only mount is an
explicit policy risk, not a default.

## Kinds

- `docker_socket_exposure`
- `docker_privileged`
- `capability_escalation` (host PID, extra caps)
- `unknown_binary` (fail-closed inside containers unless allowlisted or in-use)
- `crypto_miner_pattern`
- `unexpected_listener`
- `suspicious_process`

## Actions

Default: observe, ticket, `notify_founder`.
`block` requires `capability://hostguard/block/v1`. In Docker, prefer
stop/kill **container** or drop-cap over host PID kill — still dry-run
unless a grant file is present.
