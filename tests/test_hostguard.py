from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import hostguard


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


def _load(name: str) -> dict:
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


class ClassifyTests(unittest.TestCase):
    def test_linux_host_interview_is_observe_default(self) -> None:
        document = hostguard.classify(_load("linux-host.interview.json"))
        self.assertEqual(document["schema"], hostguard.SCHEMA_POLICY)
        self.assertEqual(document["policy"]["unknownPolicy"], "reject")
        self.assertEqual(document["policy"]["defaultAction"], "observe")
        self.assertFalse(document["policy"]["kill"]["granted"])
        kinds = {item["kind"] for item in document["classifications"]}
        self.assertIn("inventory_vs_runtime", kinds)
        self.assertIn("capability_surface", kinds)
        self.assertIn("served_artifact", kinds)
        self.assertFalse(document["policy"]["block"]["granted"])
        self.assertEqual(document["policy"]["notify"]["audience"], "founder")

    def test_top_is_not_a_threat_until_classified(self) -> None:
        document = hostguard.classify(_load("inventory-vs-runtime.interview.json"))
        decision = next(item for item in document["classifications"] if item["kind"] == "inventory_vs_runtime")
        self.assertIn("classify_before_threat", {item["do"] for item in decision["actions"]})
        self.assertIn("treat_top_as_threat", decision["forbid"])
        self.assertTrue(document["questions"])

    def test_visible_kill_is_not_a_grant(self) -> None:
        document = hostguard.classify(_load("capability-surface.interview.json"))
        decision = next(item for item in document["classifications"] if item["kind"] == "capability_surface")
        self.assertIn("require_kill_grant", {item["do"] for item in decision["actions"]})
        self.assertIn("treat_visible_kill_as_grant", decision["forbid"])
        self.assertFalse(document["policy"]["kill"]["granted"])

    def test_injected_snapshot_still_forbids_editor_as_host(self) -> None:
        document = hostguard.classify(_load("served-artifact.interview.json"))
        decision = next(item for item in document["classifications"] if item["kind"] == "served_artifact")
        self.assertIn("probe_live_host", {item["do"] for item in decision["actions"]})
        self.assertIn("treat_editor_as_host", decision["forbid"])

    def test_probe_noise_is_not_debt(self) -> None:
        document = hostguard.classify(_load("probe-noise.interview.json"))
        decision = next(item for item in document["classifications"] if item["kind"] == "probe_noise")
        self.assertIn("ignore_probe_noise", {item["do"] for item in decision["actions"]})
        self.assertIn("treat_probe_noise_as_debt", decision["forbid"])

    def test_in_use_tools_are_not_threats(self) -> None:
        document = hostguard.classify(_load("in-use-tools.interview.json"))
        decision = next(item for item in document["classifications"] if item["kind"] == "inventory_vs_runtime")
        self.assertIn("skip_in_use_tool", {item["do"] for item in decision["actions"]})
        self.assertIn("treat_in_use_tool_as_threat", decision["forbid"])
        self.assertTrue(any("in use" in q.lower() or "in-use" in q.lower() for q in document["questions"]))
        self.assertFalse(document["policy"]["block"]["granted"])
        self.assertEqual(document["policy"]["notify"]["audience"], "founder")

    def test_docker_interview_emits_security_kinds(self) -> None:
        document = hostguard.classify(_load("linux-dev-docker.interview.json"))
        kinds = {item["kind"] for item in document["classifications"]}
        for kind in (
            "suspicious_process",
            "unexpected_listener",
            "docker_socket_exposure",
            "docker_privileged",
            "capability_escalation",
            "unknown_binary",
            "crypto_miner_pattern",
        ):
            self.assertIn(kind, kinds)
        self.assertEqual(document["probe"]["dockerSock"], "none")
        self.assertEqual(set(document["probe"]["scopes"]), {"host", "container", "docker-engine"})
        self.assertEqual(document["policy"]["block"]["capability"], hostguard.BLOCK_CAPABILITY)
        self.assertIn("browser-push", document["policy"]["notify"]["channels"])

    def test_editor_view_interview_fails_closed(self) -> None:
        answers = _load("linux-host.interview.json")
        answers["probe_source"] = "editor-view"
        codes = {item.code for item in hostguard.validate_interview(answers)}
        self.assertIn("HG-SERVE-001", codes)


class ValidateTests(unittest.TestCase):
    def test_linux_example_passes(self) -> None:
        self.assertEqual(hostguard.validate_policy(_load("linux-host.hostguard.json")), [])

    def test_docker_example_passes(self) -> None:
        self.assertEqual(hostguard.validate_policy(_load("linux-dev-docker.hostguard.json")), [])

    def test_kill_without_grant_fails(self) -> None:
        codes = {item.code for item in hostguard.validate_policy(_load("invalid/kill-without-grant.hostguard.json"))}
        self.assertIn("HG-GRANT-001", codes)

    def test_missing_interval_fails(self) -> None:
        codes = {item.code for item in hostguard.validate_policy(_load("invalid/missing-interval.hostguard.json"))}
        self.assertIn("HG-INTERVAL-001", codes)

    def test_unknown_policy_preserve_fails(self) -> None:
        codes = {item.code for item in hostguard.validate_policy(_load("invalid/unknown-policy-preserve.hostguard.json"))}
        self.assertIn("HG-UNKNOWN-001", codes)

    def test_editor_source_fails_closed(self) -> None:
        document = _load("linux-host.hostguard.json")
        document["probe"]["source"] = "editor-view"
        codes = {item.code for item in hostguard.validate_policy(document)}
        self.assertIn("HG-SERVE-001", codes)

    def test_block_without_grant_fails(self) -> None:
        codes = {item.code for item in hostguard.validate_policy(_load("invalid/block-without-grant.hostguard.json"))}
        self.assertIn("HG-BLOCK-001", codes)

    def test_docker_sock_rw_fails(self) -> None:
        codes = {item.code for item in hostguard.validate_policy(_load("invalid/docker-sock-rw.hostguard.json"))}
        self.assertIn("HG-DOCKER-001", codes)

    def test_notify_audience_must_be_founder(self) -> None:
        document = _load("linux-host.hostguard.json")
        document["policy"]["notify"]["audience"] = "operator"
        codes = {item.code for item in hostguard.validate_policy(document)}
        self.assertIn("HG-NOTIFY-001", codes)

    def test_unknown_scope_fails(self) -> None:
        document = _load("linux-host.hostguard.json")
        document["probe"]["scopes"] = ["cluster"]
        codes = {item.code for item in hostguard.validate_policy(document)}
        self.assertIn("HG-SCOPE-001", codes)

    def test_inventory_missing_in_use_forbid_fails(self) -> None:
        document = _load("linux-host.hostguard.json")
        for item in document["classifications"]:
            if item["kind"] == "inventory_vs_runtime":
                item["forbid"] = ["treat_top_as_threat"]
        codes = {item.code for item in hostguard.validate_policy(document)}
        self.assertIn("HG-INUSE-001", codes)


class ProjectionTests(unittest.TestCase):
    def test_suggest_emits_document_hostguard(self) -> None:
        document = _load("linux-host.hostguard.json")
        text = hostguard.render_dsl(document)
        self.assertTrue(text.startswith("DOCUMENT HOSTGUARD"))
        self.assertIn("KIND inventory_vs_runtime", text)
        self.assertIn("KIND capability_surface", text)
        self.assertIn("KILL granted=false", text)
        self.assertIn("BLOCK granted=false", text)
        self.assertIn("AUDIENCE founder", text)
        parsed = hostguard.parse_dsl(text)
        self.assertEqual(parsed["id"], document["id"])
        self.assertEqual(parsed["probe"]["intervalSeconds"], document["probe"]["intervalSeconds"])
        self.assertEqual(
            [item["kind"] for item in parsed["classifications"]],
            [item["kind"] for item in document["classifications"]],
        )
        self.assertEqual(parsed["policy"]["notify"]["audience"], "founder")
        self.assertFalse(parsed["policy"]["block"]["granted"])


class PackSurfaceTests(unittest.TestCase):
    def test_module_has_no_host_agent(self) -> None:
        source = (ROOT / "src" / "hostguard.py").read_text(encoding="utf-8")
        for forbidden in ("read_live_snapshot", "apply_kill", "/proc", "os.kill", "SIGKILL", "watch"):
            self.assertNotIn(forbidden, source)

    def test_validate_cli(self) -> None:
        self.assertEqual(hostguard.main(["validate", str(EXAMPLES / "linux-host.hostguard.json")]), 0)

    def test_questions_prints_catalog(self) -> None:
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.assertEqual(hostguard.main(["questions"]), 0)
        self.assertIn("subject_id", buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
