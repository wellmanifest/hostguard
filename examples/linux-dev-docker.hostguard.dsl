DOCUMENT HOSTGUARD
ID linux.dev.docker
VERSION 0.2.0
SCHEMA wellmanifest.hostguard/policy/v1
PURPOSE "Classify security holes and suspicious processes on a developer host and in Docker, then notify the founder. Block stays ungranted."

PROBE
  INTERVAL 30
  SOURCE injected-snapshot
  SCOPE host
  SCOPE container
  SCOPE docker-engine
  DOCKER_SOCK none
  SIGNAL cpu
  SIGNAL ram
  SIGNAL listener
  SIGNAL docker_sock
  SIGNAL docker_privileged
  SIGNAL cap_escalation
  SIGNAL unknown_binary
  SIGNAL crypto_miner

POLICY observe-default
  UNKNOWN reject
  DEFAULT observe
  ESCALATE observe
  ESCALATE warn
  ESCALATE ticket
  ESCALATE notify_founder
  ESCALATE escalate
  KILL granted=false capability=capability://hostguard/kill/v1
  NEVER pid:1
  NEVER guardian_self
  NEVER allowlisted_instance
  BLOCK granted=false capability=capability://hostguard/block/v1
  NEVER pid:1
  NEVER guardian_self
  NEVER allowlisted_instance
  NEVER in_use_tool
  FORBID kill_without_grant
  FORBID kill_pid_1
  FORBID kill_guardian_self
  FORBID kill_allowlisted_instance
  FORBID treat_top_as_threat
  FORBID treat_in_use_tool_as_threat
  FORBID treat_editor_as_host
  FORBID treat_visible_kill_as_grant
  FORBID treat_probe_noise_as_debt
  FORBID block_without_grant
  FORBID block_pid_1
  FORBID block_guardian_self
  FORBID block_allowlisted_instance
  FORBID block_in_use_tool
  FORBID treat_visible_block_as_grant
  FORBID mount_docker_sock_rw_by_default

NOTIFY
  AUDIENCE founder
  CHANNEL browser-push
  CHANNEL desktop
  PAYLOAD wellmanifest.hostguard/founder-notify/v1

ALLOWLIST
  COMM systemd
  COMM sshd
  IMAGE nginx:alpine
  TOOL cursor
  TOOL dockerd
  COMM hostguard
  COMM guard-agent

INUSE
  SKIP true
  COMM cursor
  COMM bash
  COMM zsh
  COMM dockerd
  COMM containerd
  IMAGE nginx:alpine

THRESHOLDS
  cpuPercent 90
  ramPercent 90

CLASSIFY inventory-vs-runtime
  KIND inventory_vs_runtime
  RATIONALE "In-use developer tools and allowlisted images are inventory, not threats."
  ACTION classify_before_threat
  ACTION observe
  ACTION skip_in_use_tool
  FORBID treat_top_as_threat
  FORBID treat_in_use_tool_as_threat

CLASSIFY served-artifact
  KIND served_artifact
  RATIONALE "The product probes the live host or an injected snapshot of that host."
  ACTION probe_live_host
  FORBID treat_editor_as_host

CLASSIFY capability-surface
  KIND capability_surface
  RATIONALE "Block and kill are grants, not chrome."
  ACTION require_kill_grant
  ACTION require_block_grant
  ACTION refuse_kill
  ACTION refuse_block
  FORBID treat_visible_kill_as_grant
  FORBID treat_visible_block_as_grant
  FORBID kill_without_grant
  FORBID block_without_grant

CLASSIFY suspicious-process
  KIND suspicious_process
  SCOPE host
  RATIONALE "A process is suspicious only after allowlist and in-use tools are skipped."
  ACTION classify_before_threat
  ACTION observe
  ACTION notify_founder
  ACTION write_ticket
  FORBID treat_in_use_tool_as_threat
  FORBID block_without_grant

CLASSIFY unexpected-listener
  KIND unexpected_listener
  SCOPE host
  RATIONALE "An unexpected listener is a finding after in-use tools are skipped."
  ACTION observe
  ACTION notify_founder
  ACTION write_ticket
  ACTION refuse_block
  FORBID treat_in_use_tool_as_threat
  FORBID block_without_grant

CLASSIFY docker-socket-exposure
  KIND docker_socket_exposure
  SCOPE docker-engine
  RATIONALE "docker.sock exposure on a developer host is in-scope. Default is no RW mount."
  ACTION observe
  ACTION notify_founder
  ACTION write_ticket
  ACTION refuse_block
  FORBID treat_in_use_tool_as_threat
  FORBID block_without_grant
  FORBID mount_docker_sock_rw_by_default

CLASSIFY docker-privileged
  KIND docker_privileged
  SCOPE container
  RATIONALE "A privileged container is a capability hole."
  ACTION observe
  ACTION notify_founder
  ACTION write_ticket
  ACTION refuse_block
  FORBID treat_in_use_tool_as_threat
  FORBID block_without_grant

CLASSIFY capability-escalation
  KIND capability_escalation
  SCOPE container
  RATIONALE "Host PID namespace or extra capabilities are in-scope for a developer host."
  ACTION observe
  ACTION notify_founder
  ACTION write_ticket
  ACTION refuse_block
  FORBID treat_in_use_tool_as_threat
  FORBID block_without_grant

CLASSIFY unknown-binary
  KIND unknown_binary
  SCOPE container
  RATIONALE "Unknown binaries in containers fail closed unless allowlisted or currently in use."
  ACTION observe
  ACTION notify_founder
  ACTION write_ticket
  ACTION refuse_block
  FORBID treat_in_use_tool_as_threat
  FORBID block_without_grant

CLASSIFY crypto-miner-pattern
  KIND crypto_miner_pattern
  SCOPE host
  RATIONALE "Crypto-miner patterns are suspicious only after skipping in-use developer tools."
  ACTION observe
  ACTION notify_founder
  ACTION write_ticket
  ACTION refuse_block
  FORBID treat_in_use_tool_as_threat
  FORBID block_without_grant

QUESTIONS
  QUESTION "A visible Block control is not a POA grant. Is capability://hostguard/block/v1 explicitly granted, or is observe+ticket+notify the only effect?"
