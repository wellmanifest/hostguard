# Changelog

All notable changes to this project are documented in this file.

## [0.2.0-dev]

- Additive security kinds: suspicious_process, unexpected_listener,
  docker_socket_exposure, docker_privileged, capability_escalation,
  unknown_binary, crypto_miner_pattern.
- Scope `host` | `container` | `docker-engine`. In-use tools are inventory.
- Actions notify_founder and block; block is `capability://hostguard/block/v1`.
- Founder notify channels `browser-push` and `desktop` (payload schema;
  receipts via wellmanifest.logs). Pack remains propose-only.
- `probe.dockerSock` is `none` or `read-only`. RW is invalid.
- Document-only RAPL two-sample (`docs/RAPL.md`); the live reader stays in
  subactor/hostguard. This pack still does not probe.

## [0.1.0-dev]

- Bootstrap the hostguard domain pack on wellmanifest/dsl: interview,
  classifier, policy schema, DOCUMENT HOSTGUARD projection, and a generic
  Linux host example. This pack validates documents only; the host agent
  lives in subactor/hostguard.
