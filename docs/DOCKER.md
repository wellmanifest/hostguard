# DOCKER

## Purpose

Declare Docker-related finding kinds and how policy applies to a
**developer** host and to containerized instances of the agent.

## Syntax

```text
DOCKER
  SCOPE docker-engine
  SOCK none
  ACTION notify_founder
  BLOCK_GRANT capability://hostguard/block/v1 OPTIONAL
```

## Inputs

- validated interview/policy fields for Docker scope and `probe.dockerSock`;
- recorded `docker info`, `docker events` or `docker inspect` evidence supplied
  by the product;
- an explicit block capability only when a product proposes a block.

The pack does not read the Docker socket or enumerate containers.

## Outputs

Classification returns typed finding kinds and a propose-only action. A
product may translate a separately granted proposal to a container stop,
drop-cap or notification and must emit the corresponding external receipt.

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

## Errors

- `HG-DOCKER-001`: `dockerSock` is neither `none` nor `read-only`, or a policy
  makes a read-write socket the default;
- `HG-BLOCK-001`: a block lacks the exact hostguard capability or targets a
  protected/in-use subject;
- `HG-INUSE-001`: an in-use tool is treated as an unused threat.

## Examples

```text
DOCKER
  SCOPE container
  SOCK none
  ACTION ticket
  ACTION notify_founder
```

The example describes policy data. It performs no probe, socket mount, stop or
kill operation.
