"""Verdicts on the bundled fixtures, and every tool's own self-test, under unittest.

The self-test tables live in each tool and are not copied here: running
`--self-test` exercises the same rows a user runs, and a failing row fails
the suite because every self-test exits non-zero on any failure.
"""
import os
import sys
import unittest

from tests.support import FIXTURES, GATE, SHIP, VULNERABLE, run

# (manifest under tooling/, expected exit code, expected VERDICT line)
TRIAGE_VERDICTS = [
    ("sample-agent.json",           GATE, "GATE"),   # all three legs
    ("delete-db-agent.json",        GATE, "GATE"),   # two legs, but irreversible
    ("delete-db-agent-fixed.json",  SHIP, "SHIP"),   # the hardened version
    ("memory-agent.json",           SHIP, "SHIP"),
    ("memory-split.json",           SHIP, "SHIP"),
    ("pr-reviewer-monolithic.json", GATE, "GATE"),
    ("pr-reviewer-split.json",      SHIP, "SHIP"),
]


class FixtureVerdicts(unittest.TestCase):

    def test_triage_on_every_bundled_manifest(self):
        for name, code, verdict in TRIAGE_VERDICTS:
            with self.subTest(manifest=name):
                p = run("triage", os.path.join("tooling", name))
                self.assertEqual(p.returncode, code, p.stdout + p.stderr)
                self.assertRegex(p.stdout, r"VERDICT: %s\s" % verdict)

    def test_vulnerable_dump_gates_with_exactly_1(self):
        # Not "non-zero": 2 would mean the check did not run.
        p = run("gate", VULNERABLE)
        self.assertEqual(p.returncode, GATE, p.stdout + p.stderr)
        self.assertIn("VERDICT: GATE", p.stdout)

    def test_demo_server_end_to_end(self):
        # fetch -> gate with no third-party code. The demo is built to SHIP
        # WRONGLY offline (relay_to_partner hides its egress), so SHIP is the
        # expected -- and documented -- result.
        fetched = run("mcp_fetch", "--i-will-execute-this", "--stdio",
                      sys.executable, os.path.join("examples", "demo_mcp_server.py"))
        self.assertEqual(fetched.returncode, SHIP, fetched.stderr)
        p = run("gate", "-", stdin=fetched.stdout)
        self.assertEqual(p.returncode, SHIP, p.stdout + p.stderr)
        self.assertIn("relay_to_partner", p.stdout + fetched.stdout)


class SelfTests(unittest.TestCase):

    def test_every_tool_self_test_passes(self):
        for tool in ("audit_agent_config", "audit_allowlist", "policy_guard_hook",
                     "maestro_score"):
            with self.subTest(tool=tool):
                p = run(tool, "--self-test")
                self.assertEqual(p.returncode, 0, p.stdout[-2000:] + p.stderr)

    def test_adapter_eval_ratchet_holds(self):
        # Exits non-zero if the classifier signal ever scores BELOW the
        # keyword baseline -- the union-never-subtract property, measured.
        p = run("eval_adapter")
        self.assertEqual(p.returncode, 0, p.stdout[-2000:] + p.stderr)


class PathGuardFalsifier(unittest.TestCase):

    def test_no_rules_leaves_every_surface_uncovered(self):
        # tests/fixtures has no .claude/ of its own, and HOME is empty.
        p = run("falsify_path_guard", "--project", FIXTURES)
        self.assertEqual(p.returncode, 1, p.stderr)
        for tool in ("Write", "Edit", "NotebookEdit"):
            self.assertRegex(p.stdout, r"%s\s+UNCOVERED" % tool)

    def test_an_edit_rule_covers_the_file_tools_and_a_write_rule_is_inert(self):
        p = run("falsify_path_guard", "--project", os.path.join(FIXTURES, "path-guard"))
        # Interpreters are excluded by the vendor, so this still exits 1.
        self.assertEqual(p.returncode, 1, p.stderr)
        for tool in ("Write", "Edit", "NotebookEdit"):
            self.assertRegex(p.stdout, r"%s\s+COVERED  by Edit" % tool)
        self.assertIn("INERT RULES", p.stdout)
        self.assertRegex(p.stdout, r"Write\(\.claude/settings\.json\)\s+writes an Edit")
        self.assertRegex(p.stdout, r"python\s+UNCOVERED")


if __name__ == "__main__":
    unittest.main()
