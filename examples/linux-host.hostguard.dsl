DOCUMENT HOSTGUARD
ID linux.generic.host
VERSION 0.2.0
SCHEMA wellmanifest.hostguard/policy/v1
PURPOSE "Protect a generic Linux host running a subactor instance from runaway processes."

PROBE
  INTERVAL 30
  SOURCE live-host
  SCOPE host
  DOCKER_SOCK none
  SIGNAL cpu
  SIGNAL ram
  SIGNAL storage
  SIGNAL power
  SIGNAL fd
  SIGNAL inode
  SIGNAL zombie
  SIGNAL fork_bomb
  SIGNAL runaway

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
  COMM nginx
  CGROUP system.slice
  TOOL cursor
  TOOL bash
  COMM hostguard
  COMM guard-agent

INUSE
  SKIP true
  COMM cursor
  COMM bash
  COMM zsh
  COMM dockerd

THRESHOLDS
  cpuPercent 90
  ramPercent 90
  storagePercent 90
  powerWatts 200
  fdCount 10000
  inodePercent 90
  zombieCount 50
  forkRate 200

CLASSIFY inventory-vs-runtime
  KIND inventory_vs_runtime
  RATIONALE "A high CPU, RAM, or disk number in top is not a threat until the process is classified against the allowlist, cgroup, in-use tools, and instance services."
  ACTION classify_before_threat
  ACTION observe
  ACTION skip_in_use_tool
  FORBID treat_top_as_threat
  FORBID treat_in_use_tool_as_threat

CLASSIFY served-artifact
  KIND served_artifact
  RATIONALE "The implementing product must probe the live host (or an injected snapshot of that host). An editor buffer is not the instance."
  ACTION probe_live_host
  FORBID treat_editor_as_host

CLASSIFY capability-surface
  KIND capability_surface
  RATIONALE "A visible Kill or Block button is not a wellmanifest.poa grant. unknownPolicy=reject; observe+warn+ticket+notify_founder is the default effect."
  ACTION require_kill_grant
  ACTION require_block_grant
  ACTION refuse_kill
  ACTION refuse_block
  FORBID treat_visible_kill_as_grant
  FORBID treat_visible_block_as_grant
  FORBID kill_without_grant
  FORBID block_without_grant

QUESTIONS
  QUESTION "A visible Kill control is not a POA grant. Is capability://hostguard/kill/v1 explicitly granted, or is observe+warn+ticket the only effect?"
  QUESTION "A visible Block control is not a POA grant. Is capability://hostguard/block/v1 explicitly granted, or is observe+ticket+notify the only effect?"
  QUESTION "Founder notify uses browser-push and desktop. Without VAPID keys the product must stub the channel (receipt + local poll event) and must not invent secrets. Who is the audience? (founder only)"
