#!/usr/bin/env python3
"""Hostguard domain pack: propose-only policy documents.

This repository is a wellmanifest/dsl pack. It classifies host-threat
*documents*. It does not probe a machine, start a daemon, or kill a process.
The product that implements this contract lives in subactor/hostguard.
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
}
ACTIONS = {
    "observe",
    "warn",
    "write_ticket",
    "escalate",
    "propose_kill",
    "refuse_kill",
    "ask_clarifying_questions",
    "classify_before_threat",
    "probe_live_host",
    "require_kill_grant",
    "ignore_probe_noise",
}
FORBIDS = {
    "kill_without_grant",
    "kill_pid_1",
    "kill_guardian_self",
    "kill_allowlisted_instance",
    "treat_top_as_threat",
    "treat_editor_as_host",
    "treat_visible_kill_as_grant",
    "treat_probe_noise_as_debt",
}
SOURCES = {"live-host", "injected-snapshot"}
HOST_KINDS = {"linux-generic", "container", "vm"}
MIN_INTERVAL = 5
PROTECTED_NEVER = ("pid:1", "guardian_self", "allowlisted_instance")
REQUIRED_FORBIDS = (
    "kill_without_grant",
    "kill_pid_1",
    "kill_guardian_self",
    "kill_allowlisted_instance",
    "treat_top_as_threat",
    "treat_editor_as_host",
    "treat_visible_kill_as_grant",
    "treat_probe_noise_as_debt",
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
    return findings


def _classification(
    ident: str,
    kind: str,
    rationale: str,
    actions: Sequence[str],
    extra_forbid: Sequence[str] = (),
    questions: Sequence[str] = (),
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": ident,
        "kind": kind,
        "rationale": rationale,
        "actions": [{"do": name} for name in actions],
        "forbid": list(dict.fromkeys(extra_forbid)),
    }
    if questions:
        item["questions"] = list(questions)
    return item


def classify(answers: Mapping[str, Any]) -> dict[str, Any]:
    """Map typed interview answers to a fail-closed hostguard policy document."""

    classifications: list[dict[str, Any]] = []
    questions: list[str] = []
    granted = bool(answers.get("kill_granted"))
    source = answers.get("probe_source") or "live-host"
    treat_top = bool(answers.get("treat_top_as_threat"))
    visible_kill = bool(answers.get("visible_kill_control"))
    noise = bool(answers.get("analyzer_or_top_noise"))

    classifications.append(
        _classification(
            "inventory-vs-runtime",
            "inventory_vs_runtime",
            "A high CPU, RAM, or disk number in top is not a threat until the process is classified against the allowlist, cgroup, and instance services.",
            ("classify_before_threat", "observe"),
            ("treat_top_as_threat",),
            (NOISE_QUESTION,) if treat_top else (),
        )
    )
    if treat_top:
        questions.append(NOISE_QUESTION)

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

    classifications.append(
        _classification(
            "capability-surface",
            "capability_surface",
            "A visible Kill button is not a wellmanifest.poa grant. unknownPolicy=reject; observe+warn+ticket is the default effect.",
            ("require_kill_grant", "refuse_kill") if not granted else ("require_kill_grant",),
            ("treat_visible_kill_as_grant", "kill_without_grant"),
            (GRANT_QUESTION,) if visible_kill or not granted else (),
        )
    )
    if visible_kill or not granted:
        questions.append(GRANT_QUESTION)

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

    allowlist = []
    for comm in answers.get("allowlist_comms") or []:
        allowlist.append({"kind": "comm", "value": comm})
    for cgroup in answers.get("instance_cgroups") or []:
        allowlist.append({"kind": "cgroup", "value": cgroup})
    allowlist.append({"kind": "comm", "value": "hostguard"})

    return {
        "schema": SCHEMA_POLICY,
        "id": answers["subject_id"],
        "version": "0.1.0",
        "purpose": answers.get("purpose") or "Classify host process threats before warn, ticket, or kill.",
        "probe": {
            "intervalSeconds": int(answers["probe_interval_seconds"]),
            "source": source,
            "signals": list(answers.get("signals") or ["cpu", "ram", "storage"]),
        },
        "policy": {
            "unknownPolicy": "reject",
            "effectModel": "observe-default",
            "defaultAction": "observe",
            "escalation": ["observe", "warn", "ticket", "escalate"],
            "kill": {
                "capability": KILL_CAPABILITY,
                "granted": granted,
                "never": list(PROTECTED_NEVER),
            },
            "forbid": list(REQUIRED_FORBIDS),
        },
        "allowlist": allowlist,
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

    policy = document.get("policy") or {}
    if policy.get("unknownPolicy") != "reject":
        findings.append(Finding("HG-UNKNOWN-001", "policy.unknownPolicy must be reject", "$.policy.unknownPolicy"))
    if policy.get("defaultAction") != "observe":
        findings.append(Finding("HG-KIND-001", "defaultAction must be observe", "$.policy.defaultAction"))
    forbid = list(policy.get("forbid") or [])
    code_for = {
        "treat_top_as_threat": "HG-CLASSIFY-001",
        "treat_editor_as_host": "HG-SERVE-001",
        "treat_visible_kill_as_grant": "HG-POA-001",
        "treat_probe_noise_as_debt": "HG-NOISE-001",
        "kill_without_grant": "HG-GRANT-001",
        "kill_pid_1": "HG-PID1-001",
        "kill_guardian_self": "HG-PID1-001",
        "kill_allowlisted_instance": "HG-GRANT-001",
    }
    for required in REQUIRED_FORBIDS:
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

    kinds_seen: set[str] = set()
    for index, item in enumerate(document.get("classifications") or []):
        prefix = f"$.classifications[{index}]"
        kind = item.get("kind")
        if kind not in KINDS:
            findings.append(Finding("HG-KIND-001", f"unknown kind {kind!r}", f"{prefix}.kind"))
            continue
        kinds_seen.add(kind)
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
        if kind == "capability_surface":
            if "require_kill_grant" not in actions:
                findings.append(Finding("HG-POA-001", "capability_surface needs require_kill_grant", prefix))
            if "treat_visible_kill_as_grant" not in item_forbid:
                findings.append(Finding("HG-POA-001", "capability_surface must forbid treat_visible_kill_as_grant", prefix))
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
    lines = [
        "DOCUMENT HOSTGUARD",
        f"ID {document['id']}",
        f"VERSION {document['version']}",
        f"SCHEMA {document['schema']}",
    ]
    if document.get("purpose"):
        lines.append(f"PURPOSE {_quote(str(document['purpose']))}")
    lines += ["", "PROBE", f"  INTERVAL {probe['intervalSeconds']}", f"  SOURCE {probe['source']}"]
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
    for item in policy.get("forbid") or []:
        lines.append(f"  FORBID {item}")
    if document.get("allowlist"):
        lines += ["", "ALLOWLIST"]
        for entry in document["allowlist"]:
            lines.append(f"  {entry['kind'].upper()} {entry['value']}")
    thresholds = document.get("thresholds") or {}
    if thresholds:
        lines += ["", "THRESHOLDS"]
        for key, value in thresholds.items():
            lines.append(f"  {key} {value}")
    for item in document.get("classifications") or []:
        lines += ["", f"CLASSIFY {item['id']}", f"  KIND {item['kind']}"]
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
        "probe": {"signals": []},
        "policy": {"effectModel": "observe-default", "escalation": [], "kill": {"never": []}, "forbid": []},
        "allowlist": [],
        "thresholds": {},
        "classifications": [],
        "questions": [],
    }
    section = "root"
    current: dict[str, Any] | None = None
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
            elif head == "ALLOWLIST":
                section, current = "allowlist", document
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
                for part in rest.split():
                    key, _, value = part.partition("=")
                    if key == "granted":
                        current["kill"]["granted"] = value == "true"
                    elif key == "capability":
                        current["kill"]["capability"] = value
            elif head == "NEVER":
                current["kill"].setdefault("never", []).append(rest)
            elif head == "FORBID":
                current["forbid"].append(rest)
        elif section == "allowlist":
            document["allowlist"].append({"kind": head.lower(), "value": rest})
        elif section == "thresholds" and current is not None:
            current[head] = float(rest) if "." in rest else int(rest)
        elif section == "classify" and current is not None:
            if head == "KIND":
                current["kind"] = rest
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
