#!/usr/bin/env python3
"""Hostguard domain pack: propose-only policy documents.

This repository is a wellmanifest/dsl pack. It classifies host-threat
*documents*. It does not probe a machine, start a daemon, kill, or block.
Products: subactor/hostguard (resources) and subactor/guard-agent (holes).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


SCHEMA_POLICY = "wellmanifest.hostguard/policy/v1"
SCHEMA_INTERVIEW = "wellmanifest.hostguard/interview/v1"
IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
CAPABILITY = re.compile(r"^capability://[a-z0-9.-]+/[a-z][a-z0-9._:/-]*/v[1-9][0-9]*$")
KILL_CAPABILITY = "capability://hostguard/kill/v1"
BLOCK_CAPABILITY = "capability://hostguard/block/v1"
NOTIFY_PAYLOAD = "wellmanifest.hostguard/founder-notify/v1"

SIGNALS = {
    "cpu",
    "ram",
    "storage",
    "power",
    "fd",
    "inode",
    "zombie",
    "fork_bomb",
    "runaway",
    "listener",
    "docker_sock",
    "docker_privileged",
    "cap_escalation",
    "unknown_binary",
    "crypto_miner",
}
KINDS = {
    "inventory_vs_runtime",
    "served_artifact",
    "capability_surface",
    "allowlisted_instance",
    "guardian_self",
    "init_pid",
    "runaway_process",
    "resource_pressure",
    "fork_bomb",
    "zombie_storm",
    "probe_noise",
    "unknown_process",
    "suspicious_process",
    "unexpected_listener",
    "docker_socket_exposure",
    "docker_privileged",
    "capability_escalation",
    "unknown_binary",
    "crypto_miner_pattern",
}
ACTIONS = {
    "observe",
    "warn",
    "write_ticket",
    "ticket",
    "escalate",
    "notify_founder",
    "propose_kill",
    "refuse_kill",
    "propose_block",
    "refuse_block",
    "block",
    "ask_clarifying_questions",
    "classify_before_threat",
    "probe_live_host",
    "require_kill_grant",
    "require_block_grant",
    "skip_in_use_tool",
    "ignore_probe_noise",
}
FORBIDS = {
    "kill_without_grant",
    "kill_pid_1",
    "kill_guardian_self",
    "kill_allowlisted_instance",
    "block_without_grant",
    "block_pid_1",
    "block_guardian_self",
    "block_allowlisted_instance",
    "block_in_use_tool",
    "treat_top_as_threat",
    "treat_in_use_tool_as_threat",
    "treat_editor_as_host",
    "treat_visible_kill_as_grant",
    "treat_visible_block_as_grant",
    "treat_probe_noise_as_debt",
    "mount_docker_sock_rw_by_default",
}
SOURCES = {"live-host", "injected-snapshot"}
HOST_KINDS = {"linux-generic", "container", "vm"}
SCOPES = {"host", "container", "docker-engine"}
CHANNELS = {"browser-push", "desktop"}
DOCKER_SOCK = {"none", "read-only"}
ALLOWLIST_KINDS = {"comm", "cgroup", "pid", "image", "tool", "path", "exe"}
MIN_INTERVAL = 5
PROTECTED_NEVER = ("pid:1", "guardian_self", "allowlisted_instance")
BLOCK_NEVER = ("pid:1", "guardian_self", "allowlisted_instance", "in_use_tool")
REQUIRED_FORBIDS = (
    "kill_without_grant",
    "kill_pid_1",
    "kill_guardian_self",
    "kill_allowlisted_instance",
    "treat_top_as_threat",
    "treat_in_use_tool_as_threat",
    "treat_editor_as_host",
    "treat_visible_kill_as_grant",
    "treat_probe_noise_as_debt",
)
BLOCK_FORBIDS = (
    "block_without_grant",
    "block_pid_1",
    "block_guardian_self",
    "block_allowlisted_instance",
    "block_in_use_tool",
    "treat_visible_block_as_grant",
    "mount_docker_sock_rw_by_default",
)

NOISE_QUESTION = (
    "A high number in top is not a threat until the process is classified "
    "(allowlist, cgroup, our service). Which PIDs has an operator confirmed "
    "as foreign to this instance?"
)
GRANT_QUESTION = (
    "A visible Kill control is not a POA grant. Is capability://hostguard/"
    "kill/v1 explicitly granted, or is observe+warn+ticket the only effect?"
)
SOURCE_QUESTION = (
    "The implementing product must probe the live host, not an editor buffer. "
    "Confirm the policy source is live-host or an injected snapshot of that host."
)
INUSE_QUESTION = (
    "Tools currently in use (shells, Cursor, Docker engine, instance services) "
    "are inventory, not threats, until interview/policy says otherwise. Which "
    "comms/images has the founder confirmed as in-use on this instance?"
)
BLOCK_QUESTION = (
    "A visible Block control is not a POA grant. Is capability://hostguard/"
    "block/v1 explicitly granted, or is observe+ticket+notify the only effect?"
)
NOTIFY_QUESTION = (
    "Founder notify uses browser-push and desktop. Without VAPID keys the "
    "product must stub the channel (receipt + local poll event) and must not "
    "invent secrets. Who is the audience? (founder only)"
)


class Finding:
    def __init__(self, code: str, message: str, path: str = "$") -> None:
        self.code = code
        self.message = message
        self.path = path

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def dump_json(document: Mapping[str, Any]) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


def _is_identifier(value: Any) -> bool:
    return isinstance(value, str) and bool(IDENTIFIER.fullmatch(value))


def _is_semver(value: Any) -> bool:
    return isinstance(value, str) and bool(SEMVER.fullmatch(value))


def load_questionnaire(path: Path | None = None) -> dict[str, Any]:
    return load_json(path or repo_root() / "questions" / "interview.json")


def _as_bool(raw: str) -> bool:
    value = raw.strip().lower()
    if value in {"y", "yes", "true", "1"}:
        return True
    if value in {"n", "no", "false", "0"}:
        return False
    raise ValueError(f"expected yes/no, got {raw!r}")


def _as_list(raw: str) -> list[str]:
    return [part.strip() for part in raw.split(",") if part.strip()]


def parse_answer(question: Mapping[str, Any], raw: str) -> Any:
    kind = question["type"]
    text = raw.strip()
    if not text:
        if question.get("required"):
            raise ValueError(f"{question['id']} is required")
        return None
    if kind == "bool":
        return _as_bool(text)
    if kind == "integer":
        value = int(text)
        minimum = question.get("minimum", MIN_INTERVAL)
        if value < minimum:
            raise ValueError(f"{question['id']} must be >= {minimum}")
        return value
    if kind in {"string-list", "enum-list"}:
        items = _as_list(text)
        choices = question.get("choices")
        if choices:
            unknown = [item for item in items if item not in choices]
            if unknown:
                raise ValueError(f"{question['id']} unknown values: {unknown}")
        return items
    if kind == "enum":
        if text not in question.get("choices", []):
            raise ValueError(f"{question['id']} must be one of {question['choices']}")
        return text
    if kind == "identifier":
        value = text.replace(" ", "-").lower()
        if not _is_identifier(value):
            raise ValueError(f"{question['id']} must be a stable identifier")
        return value
    return text


def validate_interview(document: Mapping[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    if document.get("schema") != SCHEMA_INTERVIEW:
        findings.append(Finding("HG-KIND-001", "unknown interview schema", "$.schema"))
        return findings
    if not _is_identifier(document.get("subject_id")):
        findings.append(Finding("HG-KIND-001", "subject_id must be an identifier", "$.subject_id"))
    interval = document.get("probe_interval_seconds")
    if not isinstance(interval, int) or interval < MIN_INTERVAL:
        findings.append(
            Finding("HG-INTERVAL-001", f"interval must be an integer >= {MIN_INTERVAL}", "$.probe_interval_seconds")
        )
    signals = document.get("signals") or []
    if not isinstance(signals, list) or not signals:
        findings.append(Finding("HG-KIND-001", "signals must be a non-empty list", "$.signals"))
    else:
        unknown = [item for item in signals if item not in SIGNALS]
        if unknown:
            findings.append(Finding("HG-KIND-001", f"unknown signals {unknown}", "$.signals"))
    if document.get("host_kind") not in HOST_KINDS:
        findings.append(Finding("HG-KIND-001", "unknown host_kind", "$.host_kind"))
    source = document.get("probe_source")
    if source == "editor-view":
        findings.append(Finding("HG-SERVE-001", "probe_source must not be editor-view", "$.probe_source"))
    elif source not in SOURCES:
        findings.append(Finding("HG-KIND-001", "unknown probe_source", "$.probe_source"))
    scopes = document.get("scopes")
    if scopes is not None:
        if not isinstance(scopes, list) or not scopes:
            findings.append(Finding("HG-SCOPE-001", "scopes must be a non-empty list", "$.scopes"))
        else:
            unknown = [item for item in scopes if item not in SCOPES]
            if unknown:
                findings.append(Finding("HG-SCOPE-001", f"unknown scopes {unknown}", "$.scopes"))
    sock = document.get("docker_sock_policy")
    if sock is not None and sock not in DOCKER_SOCK:
        findings.append(
            Finding(
                "HG-DOCKER-001",
                "docker_sock_policy must be none or read-only; RW is not a valid default",
                "$.docker_sock_policy",
            )
        )
    channels = document.get("notify_channels")
    if channels is not None:
        unknown = [item for item in channels if item not in CHANNELS]
        if unknown:
            findings.append(Finding("HG-NOTIFY-001", f"unknown notify channels {unknown}", "$.notify_channels"))
    audience = document.get("audience")
    if audience is not None and audience != "founder":
        findings.append(Finding("HG-NOTIFY-001", "audience must be founder", "$.audience"))
    return findings


def _classification(
    ident: str,
    kind: str,
    rationale: str,
    actions: Sequence[str],
    extra_forbid: Sequence[str] = (),
    questions: Sequence[str] = (),
    scope: str | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": ident,
        "kind": kind,
        "rationale": rationale,
        "actions": [{"do": name} for name in actions],
        "forbid": list(dict.fromkeys(extra_forbid)),
    }
    if scope:
        item["scope"] = scope
    if questions:
        item["questions"] = list(questions)
    return item


def _default_scopes(answers: Mapping[str, Any]) -> list[str]:
    scopes = list(answers.get("scopes") or [])
    if scopes:
        return scopes
    if answers.get("host_kind") == "container":
        return ["container"]
    return ["host"]


def classify(answers: Mapping[str, Any]) -> dict[str, Any]:
    """Map typed interview answers to a fail-closed hostguard policy document."""

    classifications: list[dict[str, Any]] = []
    questions: list[str] = []
    granted = bool(answers.get("kill_granted"))
    block_granted = bool(answers.get("block_granted"))
    source = answers.get("probe_source") or "live-host"
    treat_top = bool(answers.get("treat_top_as_threat"))
    treat_in_use = bool(answers.get("treat_in_use_as_threat"))
    visible_kill = bool(answers.get("visible_kill_control"))
    visible_block = bool(answers.get("visible_block_control"))
    noise = bool(answers.get("analyzer_or_top_noise"))
    notify_founder = answers.get("notify_founder")
    if notify_founder is None:
        notify_founder = True
    channels = list(answers.get("notify_channels") or ["browser-push", "desktop"])
    audience = answers.get("audience") or "founder"
    scopes = _default_scopes(answers)
    docker_sock = answers.get("docker_sock_policy") or "none"
    signals = list(answers.get("signals") or ["cpu", "ram", "storage"])

    classifications.append(
        _classification(
            "inventory-vs-runtime",
            "inventory_vs_runtime",
            "A high CPU, RAM, or disk number in top is not a threat until the process is classified against the allowlist, cgroup, in-use tools, and instance services.",
            ("classify_before_threat", "observe", "skip_in_use_tool"),
            ("treat_top_as_threat", "treat_in_use_tool_as_threat"),
            (NOISE_QUESTION, INUSE_QUESTION) if treat_top or treat_in_use else (),
        )
    )
    if treat_top:
        questions.append(NOISE_QUESTION)
    if treat_in_use:
        questions.append(INUSE_QUESTION)

    classifications.append(
        _classification(
            "served-artifact",
            "served_artifact",
            "The implementing product must probe the live host (or an injected snapshot of that host). An editor buffer is not the instance.",
            ("probe_live_host",),
            ("treat_editor_as_host",),
            (SOURCE_QUESTION,) if source != "live-host" else (),
        )
    )
    if source != "live-host":
        questions.append(SOURCE_QUESTION)

    cap_actions = ["require_kill_grant", "require_block_grant"]
    if not granted:
        cap_actions.append("refuse_kill")
    if not block_granted:
        cap_actions.append("refuse_block")
    classifications.append(
        _classification(
            "capability-surface",
            "capability_surface",
            "A visible Kill or Block button is not a wellmanifest.poa grant. unknownPolicy=reject; observe+warn+ticket+notify_founder is the default effect.",
            tuple(cap_actions),
            ("treat_visible_kill_as_grant", "treat_visible_block_as_grant", "kill_without_grant", "block_without_grant"),
            (GRANT_QUESTION, BLOCK_QUESTION) if visible_kill or visible_block or not granted or not block_granted else (),
        )
    )
    if visible_kill or not granted:
        questions.append(GRANT_QUESTION)
    if visible_block or not block_granted:
        questions.append(BLOCK_QUESTION)

    if notify_founder:
        questions.append(NOTIFY_QUESTION)

    if noise:
        classifications.append(
            _classification(
                "probe-noise",
                "probe_noise",
                "Analyzer or top noise is not operational debt. Ask which processes are foreign before opening tickets.",
                ("ignore_probe_noise", "ask_clarifying_questions"),
                ("treat_probe_noise_as_debt",),
                (NOISE_QUESTION,),
            )
        )
        questions.append(NOISE_QUESTION)

    security_signals = {
        "listener": ("unexpected-listener", "unexpected_listener", "host", "An unexpected listener is a finding only after in-use tools and allowlisted services are skipped."),
        "docker_sock": ("docker-socket-exposure", "docker_socket_exposure", "docker-engine", "docker.sock exposure on a developer host is in-scope. Default is no RW mount; host-inspect is preferred."),
        "docker_privileged": ("docker-privileged", "docker_privileged", "container", "A privileged container is a capability hole. Observe+notify unless block is granted."),
        "cap_escalation": ("capability-escalation", "capability_escalation", "container", "Host PID namespace or extra capabilities are in-scope for a developer host."),
        "unknown_binary": ("unknown-binary", "unknown_binary", "container", "Unknown binaries in containers fail closed unless allowlisted or currently in use."),
        "crypto_miner": ("crypto-miner-pattern", "crypto_miner_pattern", "host", "Crypto-miner patterns are suspicious only after skipping in-use developer tools."),
    }
    want_security = bool(set(signals) & set(security_signals)) or "docker-engine" in scopes or "container" in scopes
    if want_security:
        classifications.append(
            _classification(
                "suspicious-process",
                "suspicious_process",
                "A process is suspicious only after allowlist and in-use tools are skipped. Unused unknown processes may be ticketed and the founder notified.",
                ("classify_before_threat", "observe", "notify_founder", "write_ticket"),
                ("treat_in_use_tool_as_threat", "block_without_grant"),
                (INUSE_QUESTION,),
                scope="host" if "host" in scopes else scopes[0],
            )
        )
        for signal, (ident, kind, scope, rationale) in security_signals.items():
            if signal in signals or (signal.startswith("docker") and "docker-engine" in scopes) or (
                signal in {"cap_escalation", "unknown_binary", "docker_privileged"} and "container" in scopes
            ):
                actions = ("observe", "notify_founder", "write_ticket", "propose_block" if block_granted else "refuse_block")
                classifications.append(
                    _classification(
                        ident,
                        kind,
                        rationale,
                        actions,
                        ("treat_in_use_tool_as_threat", "block_without_grant", "mount_docker_sock_rw_by_default"),
                        scope=scope if scope in scopes else scopes[0],
                    )
                )

    allowlist = []
    for comm in answers.get("allowlist_comms") or []:
        allowlist.append({"kind": "comm", "value": comm})
    for cgroup in answers.get("instance_cgroups") or []:
        allowlist.append({"kind": "cgroup", "value": cgroup})
    for image in answers.get("allowlist_images") or []:
        allowlist.append({"kind": "image", "value": image})
    for tool in answers.get("in_use_tools") or ["cursor", "bash", "zsh", "dockerd", "containerd"]:
        allowlist.append({"kind": "tool", "value": tool})
    allowlist.append({"kind": "comm", "value": "hostguard"})
    allowlist.append({"kind": "comm", "value": "guard-agent"})

    in_use = {
        "comms": list(answers.get("in_use_tools") or ["cursor", "bash", "zsh", "dockerd", "containerd"]),
        "images": list(answers.get("allowlist_images") or []),
        "skipUntilInterview": True,
    }

    forbid = list(REQUIRED_FORBIDS) + list(BLOCK_FORBIDS)

    return {
        "schema": SCHEMA_POLICY,
        "id": answers["subject_id"],
        "version": "0.2.0",
        "purpose": answers.get("purpose") or "Classify host process threats before warn, ticket, notify, or block.",
        "probe": {
            "intervalSeconds": int(answers["probe_interval_seconds"]),
            "source": source,
            "signals": signals,
            "scopes": scopes,
            "dockerSock": docker_sock if docker_sock in DOCKER_SOCK else "none",
        },
        "policy": {
            "unknownPolicy": "reject",
            "effectModel": "observe-default",
            "defaultAction": "observe",
            "escalation": ["observe", "warn", "ticket", "notify_founder", "escalate"],
            "kill": {
                "capability": KILL_CAPABILITY,
                "granted": granted,
                "never": list(PROTECTED_NEVER),
            },
            "block": {
                "capability": BLOCK_CAPABILITY,
                "granted": block_granted,
                "never": list(BLOCK_NEVER),
            },
            "notify": {
                "audience": audience,
                "channels": channels,
                "payloadSchema": NOTIFY_PAYLOAD,
            },
            "forbid": list(dict.fromkeys(forbid)),
        },
        "allowlist": allowlist,
        "inUse": in_use,
        "thresholds": {
            "cpuPercent": 90,
            "ramPercent": 90,
            "storagePercent": 90,
            "powerWatts": 200,
            "fdCount": 10000,
            "inodePercent": 90,
            "zombieCount": 50,
            "forkRate": 200,
        },
        "classifications": classifications,
        "questions": list(dict.fromkeys(questions)),
    }


def validate_policy(document: Mapping[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    if document.get("schema") != SCHEMA_POLICY:
        findings.append(Finding("HG-KIND-001", "unknown policy schema", "$.schema"))
        return findings
    if not _is_identifier(document.get("id")):
        findings.append(Finding("HG-KIND-001", "id must be an identifier", "$.id"))
    if not _is_semver(document.get("version")):
        findings.append(Finding("HG-KIND-001", "version must be semver", "$.version"))

    probe = document.get("probe") or {}
    interval = probe.get("intervalSeconds")
    if not isinstance(interval, int) or interval < MIN_INTERVAL:
        findings.append(
            Finding(
                "HG-INTERVAL-001",
                f"probe.intervalSeconds must be an integer >= {MIN_INTERVAL} and must live in the document",
                "$.probe.intervalSeconds",
            )
        )
    source = probe.get("source")
    if source == "editor-view":
        findings.append(Finding("HG-SERVE-001", "probe.source must not be editor-view", "$.probe.source"))
    elif source not in SOURCES:
        findings.append(Finding("HG-KIND-001", "unknown probe.source", "$.probe.source"))
    signals = probe.get("signals") or []
    if not isinstance(signals, list) or not signals:
        findings.append(Finding("HG-KIND-001", "probe.signals must be non-empty", "$.probe.signals"))
    else:
        unknown = [item for item in signals if item not in SIGNALS]
        if unknown:
            findings.append(Finding("HG-KIND-001", f"unknown signals {unknown}", "$.probe.signals"))
    scopes = probe.get("scopes")
    if scopes is not None:
        if not isinstance(scopes, list) or not scopes:
            findings.append(Finding("HG-SCOPE-001", "probe.scopes must be a non-empty list", "$.probe.scopes"))
        else:
            unknown_scopes = [item for item in scopes if item not in SCOPES]
            if unknown_scopes:
                findings.append(Finding("HG-SCOPE-001", f"unknown probe.scopes {unknown_scopes}", "$.probe.scopes"))
    sock = probe.get("dockerSock")
    if sock is not None and sock not in DOCKER_SOCK:
        findings.append(
            Finding("HG-DOCKER-001", "probe.dockerSock must be none or read-only", "$.probe.dockerSock")
        )

    policy = document.get("policy") or {}
    if policy.get("unknownPolicy") != "reject":
        findings.append(Finding("HG-UNKNOWN-001", "policy.unknownPolicy must be reject", "$.policy.unknownPolicy"))
    if policy.get("defaultAction") != "observe":
        findings.append(Finding("HG-KIND-001", "defaultAction must be observe", "$.policy.defaultAction"))
    forbid = list(policy.get("forbid") or [])
    code_for = {
        "treat_top_as_threat": "HG-CLASSIFY-001",
        "treat_in_use_tool_as_threat": "HG-INUSE-001",
        "treat_editor_as_host": "HG-SERVE-001",
        "treat_visible_kill_as_grant": "HG-POA-001",
        "treat_visible_block_as_grant": "HG-BLOCK-001",
        "treat_probe_noise_as_debt": "HG-NOISE-001",
        "kill_without_grant": "HG-GRANT-001",
        "kill_pid_1": "HG-PID1-001",
        "kill_guardian_self": "HG-PID1-001",
        "kill_allowlisted_instance": "HG-GRANT-001",
        "block_without_grant": "HG-BLOCK-001",
        "block_pid_1": "HG-PID1-001",
        "block_guardian_self": "HG-PID1-001",
        "block_allowlisted_instance": "HG-BLOCK-001",
        "block_in_use_tool": "HG-INUSE-001",
        "mount_docker_sock_rw_by_default": "HG-DOCKER-001",
    }
    required_forbids = list(REQUIRED_FORBIDS)
    if policy.get("block") is not None:
        required_forbids.extend(BLOCK_FORBIDS)
    for required in required_forbids:
        if required not in forbid:
            findings.append(Finding(code_for[required], f"policy.forbid missing {required}", "$.policy.forbid"))
    unknown_forbid = [item for item in forbid if item not in FORBIDS]
    if unknown_forbid:
        findings.append(Finding("HG-KIND-001", f"unknown forbid {unknown_forbid}", "$.policy.forbid"))

    kill = policy.get("kill") or {}
    never = list(kill.get("never") or [])
    for required in PROTECTED_NEVER:
        if required not in never:
            findings.append(Finding("HG-PID1-001", f"kill.never missing {required}", "$.policy.kill.never"))
    capability = kill.get("capability")
    granted = bool(kill.get("granted"))
    if granted:
        if not isinstance(capability, str) or not CAPABILITY.fullmatch(capability):
            findings.append(Finding("HG-GRANT-001", "granted kill requires a capability:// ref", "$.policy.kill.capability"))
        elif capability != KILL_CAPABILITY:
            findings.append(Finding("HG-GRANT-001", f"unknown kill capability {capability!r}", "$.policy.kill.capability"))
    elif capability not in {None, KILL_CAPABILITY}:
        findings.append(Finding("HG-GRANT-001", "ungranted kill must not declare a foreign capability", "$.policy.kill.capability"))

    block = policy.get("block")
    if block is not None:
        block_never = list(block.get("never") or [])
        for required in BLOCK_NEVER:
            if required not in block_never:
                findings.append(Finding("HG-PID1-001", f"block.never missing {required}", "$.policy.block.never"))
        block_cap = block.get("capability")
        block_granted = bool(block.get("granted"))
        if block_granted:
            if not isinstance(block_cap, str) or not CAPABILITY.fullmatch(block_cap):
                findings.append(Finding("HG-BLOCK-001", "granted block requires a capability:// ref", "$.policy.block.capability"))
            elif block_cap != BLOCK_CAPABILITY:
                findings.append(Finding("HG-BLOCK-001", f"unknown block capability {block_cap!r}", "$.policy.block.capability"))
        elif block_cap not in {None, BLOCK_CAPABILITY}:
            findings.append(Finding("HG-BLOCK-001", "ungranted block must not declare a foreign capability", "$.policy.block.capability"))

    notify = policy.get("notify")
    if notify is not None:
        if notify.get("audience") != "founder":
            findings.append(Finding("HG-NOTIFY-001", "notify.audience must be founder", "$.policy.notify.audience"))
        notify_channels = notify.get("channels") or []
        if not notify_channels:
            findings.append(Finding("HG-NOTIFY-001", "notify.channels must be non-empty", "$.policy.notify.channels"))
        unknown_channels = [item for item in notify_channels if item not in CHANNELS]
        if unknown_channels:
            findings.append(Finding("HG-NOTIFY-001", f"unknown notify channels {unknown_channels}", "$.policy.notify.channels"))
        payload = notify.get("payloadSchema")
        if payload not in {None, NOTIFY_PAYLOAD}:
            findings.append(Finding("HG-NOTIFY-001", "unknown notify payload schema", "$.policy.notify.payloadSchema"))

    for index, entry in enumerate(document.get("allowlist") or []):
        kind = entry.get("kind")
        if kind not in ALLOWLIST_KINDS:
            findings.append(Finding("HG-KIND-001", f"unknown allowlist kind {kind!r}", f"$.allowlist[{index}].kind"))

    kinds_seen: set[str] = set()
    for index, item in enumerate(document.get("classifications") or []):
        prefix = f"$.classifications[{index}]"
        kind = item.get("kind")
        if kind not in KINDS:
            findings.append(Finding("HG-KIND-001", f"unknown kind {kind!r}", f"{prefix}.kind"))
            continue
        kinds_seen.add(kind)
        scope = item.get("scope")
        if scope is not None and scope not in SCOPES:
            findings.append(Finding("HG-SCOPE-001", f"unknown classification scope {scope!r}", f"{prefix}.scope"))
        for action in item.get("actions") or []:
            if action.get("do") not in ACTIONS:
                findings.append(Finding("HG-KIND-001", f"unknown action {action.get('do')!r}", f"{prefix}.actions"))
        for item_forbid in item.get("forbid") or []:
            if item_forbid not in FORBIDS:
                findings.append(Finding("HG-KIND-001", f"unknown forbid {item_forbid!r}", f"{prefix}.forbid"))
        actions = {entry.get("do") for entry in item.get("actions") or []}
        item_forbid = item.get("forbid") or []
        if kind == "inventory_vs_runtime":
            if "classify_before_threat" not in actions:
                findings.append(Finding("HG-CLASSIFY-001", "inventory_vs_runtime needs classify_before_threat", prefix))
            if "treat_top_as_threat" not in item_forbid:
                findings.append(Finding("HG-CLASSIFY-001", "inventory_vs_runtime must forbid treat_top_as_threat", prefix))
            if "treat_in_use_tool_as_threat" not in item_forbid:
                findings.append(Finding("HG-INUSE-001", "inventory_vs_runtime must forbid treat_in_use_tool_as_threat", prefix))
        if kind == "capability_surface":
            if "require_kill_grant" not in actions:
                findings.append(Finding("HG-POA-001", "capability_surface needs require_kill_grant", prefix))
            if "treat_visible_kill_as_grant" not in item_forbid:
                findings.append(Finding("HG-POA-001", "capability_surface must forbid treat_visible_kill_as_grant", prefix))
            if block is not None:
                if "require_block_grant" not in actions:
                    findings.append(Finding("HG-BLOCK-001", "capability_surface needs require_block_grant when block is declared", prefix))
                if "treat_visible_block_as_grant" not in item_forbid:
                    findings.append(Finding("HG-BLOCK-001", "capability_surface must forbid treat_visible_block_as_grant when block is declared", prefix))
        if kind == "served_artifact" and "treat_editor_as_host" not in item_forbid:
            findings.append(Finding("HG-SERVE-001", "served_artifact must forbid treat_editor_as_host", prefix))
        if kind == "probe_noise" and "treat_probe_noise_as_debt" not in item_forbid:
            findings.append(Finding("HG-NOISE-001", "probe_noise must forbid treat_probe_noise_as_debt", prefix))

    if "inventory_vs_runtime" not in kinds_seen:
        findings.append(Finding("HG-CLASSIFY-001", "policy must classify inventory_vs_runtime", "$.classifications"))
    if "capability_surface" not in kinds_seen:
        findings.append(Finding("HG-POA-001", "policy must classify capability_surface", "$.classifications"))
    if "served_artifact" not in kinds_seen:
        findings.append(Finding("HG-SERVE-001", "policy must classify served_artifact", "$.classifications"))
    return findings


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_dsl(document: Mapping[str, Any]) -> str:
    probe = document["probe"]
    policy = document["policy"]
    kill = policy.get("kill") or {}
    block = policy.get("block") or {}
    notify = policy.get("notify") or {}
    lines = [
        "DOCUMENT HOSTGUARD",
        f"ID {document['id']}",
        f"VERSION {document['version']}",
        f"SCHEMA {document['schema']}",
    ]
    if document.get("purpose"):
        lines.append(f"PURPOSE {_quote(str(document['purpose']))}")
    lines += ["", "PROBE", f"  INTERVAL {probe['intervalSeconds']}", f"  SOURCE {probe['source']}"]
    for scope in probe.get("scopes") or []:
        lines.append(f"  SCOPE {scope}")
    if probe.get("dockerSock"):
        lines.append(f"  DOCKER_SOCK {probe['dockerSock']}")
    for signal in probe.get("signals") or []:
        lines.append(f"  SIGNAL {signal}")
    lines += ["", "POLICY observe-default", f"  UNKNOWN {policy.get('unknownPolicy', 'reject')}", f"  DEFAULT {policy.get('defaultAction', 'observe')}"]
    for step in policy.get("escalation") or []:
        lines.append(f"  ESCALATE {step}")
    lines.append(
        "  KILL granted={granted} capability={capability}".format(
            granted=str(bool(kill.get("granted"))).lower(),
            capability=kill.get("capability") or KILL_CAPABILITY,
        )
    )
    for item in kill.get("never") or []:
        lines.append(f"  NEVER {item}")
    if block:
        lines.append(
            "  BLOCK granted={granted} capability={capability}".format(
                granted=str(bool(block.get("granted"))).lower(),
                capability=block.get("capability") or BLOCK_CAPABILITY,
            )
        )
        for item in block.get("never") or []:
            lines.append(f"  NEVER {item}")
    for item in policy.get("forbid") or []:
        lines.append(f"  FORBID {item}")
    if notify:
        lines += ["", "NOTIFY", f"  AUDIENCE {notify.get('audience', 'founder')}"]
        for channel in notify.get("channels") or []:
            lines.append(f"  CHANNEL {channel}")
        if notify.get("payloadSchema"):
            lines.append(f"  PAYLOAD {notify['payloadSchema']}")
    if document.get("allowlist"):
        lines += ["", "ALLOWLIST"]
        for entry in document["allowlist"]:
            lines.append(f"  {entry['kind'].upper()} {entry['value']}")
    in_use = document.get("inUse") or {}
    if in_use:
        lines += ["", "INUSE"]
        if "skipUntilInterview" in in_use:
            lines.append(f"  SKIP {str(bool(in_use.get('skipUntilInterview'))).lower()}")
        for comm in in_use.get("comms") or []:
            lines.append(f"  COMM {comm}")
        for image in in_use.get("images") or []:
            lines.append(f"  IMAGE {image}")
    thresholds = document.get("thresholds") or {}
    if thresholds:
        lines += ["", "THRESHOLDS"]
        for key, value in thresholds.items():
            lines.append(f"  {key} {value}")
    for item in document.get("classifications") or []:
        lines += ["", f"CLASSIFY {item['id']}", f"  KIND {item['kind']}"]
        if item.get("scope"):
            lines.append(f"  SCOPE {item['scope']}")
        if item.get("rationale"):
            lines.append(f"  RATIONALE {_quote(item['rationale'])}")
        for action in item.get("actions") or []:
            lines.append(f"  ACTION {action['do']}")
        for forbid in item.get("forbid") or []:
            lines.append(f"  FORBID {forbid}")
        for question in item.get("questions") or []:
            lines.append(f"  QUESTION {_quote(question)}")
    if document.get("questions"):
        lines += ["", "QUESTIONS"]
        for question in document["questions"]:
            lines.append(f"  QUESTION {_quote(question)}")
    lines.append("")
    return "\n".join(lines)


def _unquote(value: str) -> str:
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] == '"':
        return bytes(text[1:-1], "utf-8").decode("unicode_escape")
    return text


def parse_dsl(text: str) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema": SCHEMA_POLICY,
        "probe": {"signals": [], "scopes": []},
        "policy": {
            "effectModel": "observe-default",
            "escalation": [],
            "kill": {"never": []},
            "forbid": [],
        },
        "allowlist": [],
        "inUse": {"comms": [], "images": []},
        "thresholds": {},
        "classifications": [],
        "questions": [],
    }
    section = "root"
    current: dict[str, Any] | None = None
    never_owner: dict[str, Any] | None = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        tokens = line.strip().split(None, 1)
        head = tokens[0]
        rest = tokens[1] if len(tokens) > 1 else ""
        if indent == 0:
            if head == "DOCUMENT":
                continue
            if head == "ID":
                document["id"] = rest
            elif head == "VERSION":
                document["version"] = rest
            elif head == "SCHEMA":
                document["schema"] = rest
            elif head == "PURPOSE":
                document["purpose"] = _unquote(rest)
            elif head == "PROBE":
                section, current = "probe", document["probe"]
            elif head == "POLICY":
                section, current = "policy", document["policy"]
                never_owner = current["kill"]
            elif head == "NOTIFY":
                section = "notify"
                current = document["policy"].setdefault(
                    "notify", {"channels": [], "audience": "founder", "payloadSchema": NOTIFY_PAYLOAD}
                )
            elif head == "ALLOWLIST":
                section, current = "allowlist", document
            elif head == "INUSE":
                section, current = "inuse", document["inUse"]
            elif head == "THRESHOLDS":
                section, current = "thresholds", document["thresholds"]
            elif head == "CLASSIFY":
                section = "classify"
                current = {"id": rest, "actions": [], "forbid": [], "questions": []}
                document["classifications"].append(current)
            elif head == "QUESTIONS":
                section, current = "questions", document
            continue
        if section == "probe" and current is not None:
            if head == "INTERVAL":
                current["intervalSeconds"] = int(rest)
            elif head == "SOURCE":
                current["source"] = rest
            elif head == "SCOPE":
                current.setdefault("scopes", []).append(rest)
            elif head == "DOCKER_SOCK":
                current["dockerSock"] = rest
            elif head == "SIGNAL":
                current["signals"].append(rest)
        elif section == "policy" and current is not None:
            if head == "UNKNOWN":
                current["unknownPolicy"] = rest
            elif head == "DEFAULT":
                current["defaultAction"] = rest
            elif head == "ESCALATE":
                current["escalation"].append(rest)
            elif head == "KILL":
                current["kill"]["capability"] = KILL_CAPABILITY
                never_owner = current["kill"]
                for part in rest.split():
                    key, _, value = part.partition("=")
                    if key == "granted":
                        current["kill"]["granted"] = value == "true"
                    elif key == "capability":
                        current["kill"]["capability"] = value
            elif head == "BLOCK":
                block = current.setdefault("block", {"never": [], "capability": BLOCK_CAPABILITY})
                never_owner = block
                for part in rest.split():
                    key, _, value = part.partition("=")
                    if key == "granted":
                        block["granted"] = value == "true"
                    elif key == "capability":
                        block["capability"] = value
            elif head == "NEVER":
                target = never_owner if never_owner is not None else current["kill"]
                target.setdefault("never", []).append(rest)
            elif head == "FORBID":
                current["forbid"].append(rest)
        elif section == "notify" and current is not None:
            if head == "AUDIENCE":
                current["audience"] = rest
            elif head == "CHANNEL":
                current.setdefault("channels", []).append(rest)
            elif head == "PAYLOAD":
                current["payloadSchema"] = rest
        elif section == "allowlist":
            document["allowlist"].append({"kind": head.lower(), "value": rest})
        elif section == "inuse" and current is not None:
            if head == "SKIP":
                current["skipUntilInterview"] = rest == "true"
            elif head == "COMM":
                current.setdefault("comms", []).append(rest)
            elif head == "IMAGE":
                current.setdefault("images", []).append(rest)
        elif section == "thresholds" and current is not None:
            current[head] = float(rest) if "." in rest else int(rest)
        elif section == "classify" and current is not None:
            if head == "KIND":
                current["kind"] = rest
            elif head == "SCOPE":
                current["scope"] = rest
            elif head == "RATIONALE":
                current["rationale"] = _unquote(rest)
            elif head == "ACTION":
                current["actions"].append({"do": rest})
            elif head == "FORBID":
                current["forbid"].append(rest)
            elif head == "QUESTION":
                current["questions"].append(_unquote(rest))
        elif section == "questions" and head == "QUESTION":
            document["questions"].append(_unquote(rest))
    if not document["probe"].get("scopes"):
        document["probe"].pop("scopes", None)
    in_use = document.get("inUse") or {}
    if not in_use.get("comms") and not in_use.get("images") and "skipUntilInterview" not in in_use:
        document.pop("inUse", None)
    if not (document.get("policy") or {}).get("notify", {}).get("channels") and "notify" in document.get("policy", {}):
        if document["policy"]["notify"] == {"channels": [], "audience": "founder", "payloadSchema": NOTIFY_PAYLOAD}:
            document["policy"].pop("notify", None)
    for item in document["classifications"]:
        if not item.get("questions"):
            item.pop("questions", None)
    return document


def render_findings(findings: Sequence[Finding], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(
            {
                "schema": "wellmanifest.hostguard/check-result/v1",
                "status": "failed" if findings else "passed",
                "findings": [item.as_dict() for item in findings],
            },
            indent=2,
            sort_keys=True,
        )
    if not findings:
        return "ok"
    return "\n".join(f"{item.code} {item.path}: {item.message}" for item in findings)


def _read_document(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix in {".dsl", ".hostguard"} or text.lstrip().startswith("DOCUMENT HOSTGUARD"):
        return parse_dsl(text)
    return json.loads(text)


def cmd_questions() -> int:
    for index, question in enumerate(load_questionnaire()["questions"], start=1):
        required = "required" if question.get("required") else "optional"
        print(f"{index:02d}. [{question['id']}] ({required}) {question['prompt']}")
    return 0


def run_interview(answers_path: Path | None, output: Path | None, output_format: str) -> int:
    if answers_path is None:
        answers: dict[str, Any] = {"schema": SCHEMA_INTERVIEW}
        for question in load_questionnaire()["questions"]:
            value = parse_answer(question, input(f"{question['prompt']}\n> "))
            if value is not None:
                answers[question["id"]] = value
    else:
        answers = load_json(answers_path)
    findings = validate_interview(answers)
    if findings:
        print(render_findings(findings, "text"), file=sys.stderr)
        return 1
    document = classify(answers)
    payload = render_dsl(document) if output_format == "dsl" else dump_json(document)
    if output:
        output.write_text(payload, encoding="utf-8")
    else:
        sys.stdout.write(payload)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hostguard", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    interview = sub.add_parser("interview", help="classify saved answers into a policy document")
    interview.add_argument("--answers", type=Path)
    interview.add_argument("--output", type=Path)
    interview.add_argument("--format", choices=("json", "dsl"), default="json")
    classify_cmd = sub.add_parser("classify", help="classify interview JSON into a policy document")
    classify_cmd.add_argument("answers", type=Path)
    classify_cmd.add_argument("--format", choices=("json", "dsl"), default="json")
    suggest = sub.add_parser("suggest", help="emit the DOCUMENT HOSTGUARD projection")
    suggest.add_argument("document", type=Path)
    validate = sub.add_parser("validate", help="validate a policy or interview document")
    validate.add_argument("document", type=Path)
    validate.add_argument("--format", choices=("text", "json"), default="text")
    sub.add_parser("questions", help="print the questionnaire")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _parser().parse_args(list(argv) if argv is not None else None)
    if args.command == "questions":
        return cmd_questions()
    if args.command == "interview":
        return run_interview(args.answers, args.output, args.format)
    if args.command == "classify":
        answers = load_json(args.answers)
        findings = validate_interview(answers)
        if findings:
            print(render_findings(findings, "text"), file=sys.stderr)
            return 1
        document = classify(answers)
        sys.stdout.write(render_dsl(document) if args.format == "dsl" else dump_json(document))
        return 0
    if args.command == "suggest":
        document = _read_document(args.document)
        findings = validate_policy(document)
        if findings:
            print(render_findings(findings, "text"), file=sys.stderr)
            return 1
        sys.stdout.write(render_dsl(document))
        return 0
    document = _read_document(args.document)
    findings = validate_interview(document) if document.get("schema") == SCHEMA_INTERVIEW else validate_policy(document)
    print(render_findings(findings, args.format))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
