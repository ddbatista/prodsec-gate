"""prodsec-gate's verdicts, at the process boundary and through an injected backend.

The CLI cannot inject a model, so the --live path is driven in-process through
main(backend=...): the same code path, minus the network.
"""
import contextlib
import io
import json
import os
import sys
import unittest

from tests.test_contract import ERROR, GATE, ROOT, SHIP, TOOLING, run

sys.path.insert(0, TOOLING)
import gate  # noqa: E402

VULNERABLE = os.path.join("tooling", "mcp-dump.json")
HARMLESS = os.path.join("tests", "fixtures", "harmless.tools.json")


def gate_json(*args, stdin=""):
    p = run("gate", *args, "--json", stdin=stdin)
    return p, (json.loads(p.stdout) if p.stdout.strip() else None)


def gate_in_process(argv, backend, stdin=""):
    """Run gate.main with an injected backend; return (exit code, stdout)."""
    out = io.StringIO()
    old_stdin = sys.stdin
    sys.stdin = io.StringIO(stdin)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = gate.main(argv, backend=backend)
    finally:
        sys.stdin = old_stdin
    return rc, out.getvalue()


class JsonMode(unittest.TestCase):

    def test_json_carries_the_verdict_and_its_exit_code(self):
        p, m = gate_json(VULNERABLE)
        self.assertEqual(p.returncode, GATE, p.stderr)
        self.assertEqual(m["verdict"], "GATE")
        for key in ("classifier", "floor_recall_on_corpus", "failed_closed", "basis"):
            self.assertIn(key, m["instrument"])

    def test_json_on_a_harmless_dump_ships(self):
        p, m = gate_json(HARMLESS)
        self.assertEqual(p.returncode, SHIP, p.stderr)
        self.assertEqual(m["verdict"], "SHIP")

    def test_json_on_bad_input_is_not_audited(self):
        for stdin in ("", "not json", '{"tools": []}'):
            with self.subTest(stdin=stdin):
                p, _ = gate_json("-", stdin=stdin)
                self.assertEqual(p.returncode, ERROR, p.stderr)


class DumpShapes(unittest.TestCase):

    def test_all_three_shapes_give_the_same_manifest(self):
        with open(os.path.join(ROOT, VULNERABLE)) as f:
            tools = json.load(f)["result"]["tools"]
        shapes = {
            "json-rpc response": {"jsonrpc": "2.0", "id": 1, "result": {"tools": tools}},
            "bare {tools}": {"tools": tools},
            "bare array": tools,
        }
        manifests = {}
        for label, dump in shapes.items():
            p, m = gate_json("-", stdin=json.dumps(dump))
            self.assertEqual(p.returncode, GATE, "%s: %s" % (label, p.stderr))
            manifests[label] = m
        first = manifests.pop("json-rpc response")
        for label, m in manifests.items():
            self.assertEqual(m, first, label)


class LivePath(unittest.TestCase):

    def test_an_injected_classifier_runs_through_the_same_parser(self):
        # SHIP offline. A classifier that reports all three legs for every
        # tool must be able to ADD them, so the same dump becomes GATE.
        def sees_everything(system, payload):
            return "untrusted_input\nprivate_data\nexternal_comms"

        offline_rc, _ = gate_in_process([HARMLESS], backend=None)
        rc, out = gate_in_process([HARMLESS, "--json"], backend=sees_everything)
        self.assertEqual(offline_rc, SHIP)
        self.assertEqual(rc, GATE)
        m = json.loads(out)
        self.assertEqual(m["verdict"], "GATE")
        self.assertEqual(m["instrument"]["failed_closed"], [])
        self.assertIn("external_comms", m["tools"][0]["capabilities"])


if __name__ == "__main__":
    unittest.main()
