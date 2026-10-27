"""The exit-code contract, tested at the process boundary.

    0  pass       1  finding       2  not audited (bad input, nothing to audit, crash)

CI reads exit codes, not prose, so that is what these tests assert. Every row
runs a real command as a subprocess. See docs/design-notes.md once it exists;
until then the README's "Exit codes are the interface" section is the source.
"""
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLING = os.path.join(ROOT, "tooling")

SHIP, GATE, ERROR = 0, 1, 2


def run(script, *args, stdin=""):
    """Run tooling/<script>.py the way a CI job would; return the CompletedProcess."""
    return subprocess.run(
        [sys.executable, os.path.join(TOOLING, script + ".py")] + list(args),
        input=stdin, capture_output=True, text=True, cwd=ROOT, timeout=60)


# Every way a command can be handed nothing to audit. Each row:
#   (command, argv, stdin, text the stderr must contain)
# A new command is not done until it has rows here.
NOT_AUDITED = [
    ("triage", ["does-not-exist.json"], "", "does-not-exist.json"),
    ("triage", ["-"], "", "pipefail"),                  # upstream failed silently
    ("triage", ["-"], "not json", "not JSON"),
    ("triage", ["-"], '{"tools": []}', "no tools"),
    ("triage", ["-"], '{"agent": "x"}', "no tools"),
    # Valid JSON that crashes the assessment: Python's own exit code for an
    # uncaught exception is 1, the same as GATE.
    ("triage", ["-"], "[]", "internal error"),
    ("triage", ["-"], '{"tools": [{"capabilities": ["state_change"],'
                      ' "reversible": false}]}', "internal error"),
]


class NotAuditedContract(unittest.TestCase):

    def test_every_row_exits_2_with_an_error_and_no_traceback(self):
        for command, argv, stdin, says in NOT_AUDITED:
            with self.subTest(command=command, argv=argv, stdin=stdin):
                p = run(command, *argv, stdin=stdin)
                self.assertEqual(p.returncode, ERROR, p.stdout + p.stderr)
                self.assertNotIn("Traceback", p.stderr)
                self.assertTrue(p.stderr.startswith("ERROR:"), p.stderr)
                self.assertIn(says, p.stderr)


class TriageContract(unittest.TestCase):

    def test_no_arguments_is_not_audited(self):
        p = run("triage")
        self.assertEqual(p.returncode, ERROR, p.stdout + p.stderr)
        self.assertIn("usage", (p.stdout + p.stderr).lower())

    def test_human_gated_trifecta_passes_and_says_why(self):
        manifest = ('{"human_in_loop": true, "tools": [{"name": "t", "capabilities":'
                    ' ["untrusted_input", "private_data", "external_comms"]}]}')
        p = run("triage", "-", stdin=manifest)
        self.assertEqual(p.returncode, SHIP, p.stdout + p.stderr)
        self.assertIn("SHIP*", p.stdout)
        self.assertIn("human gates", p.stdout)


def run_entrypoint(body):
    """Run a throwaway command whose main() is `body`, wrapped like the real ones.

    Injects the failure directly, so this coverage does not depend on some
    input happening to crash a real command today.
    """
    code = ("import sys; sys.path.insert(0, %r); import _cli\n"
            "@_cli.entrypoint\n"
            "def main():\n    %s\n"
            "sys.exit(main())\n" % (TOOLING, body))
    return subprocess.run([sys.executable, "-c", code], capture_output=True,
                          text=True, timeout=60)


class EntrypointContract(unittest.TestCase):

    def test_injected_exception_is_not_a_finding(self):
        p = run_entrypoint("raise RuntimeError('boom')")
        self.assertEqual(p.returncode, ERROR, p.stderr)
        self.assertNotIn("Traceback", p.stderr)
        self.assertIn("boom", p.stderr)

    def test_falling_off_the_end_is_not_a_pass(self):
        # sys.exit(None) is exit 0: a gate that never reached its verdict
        # would SHIP.
        p = run_entrypoint("pass")
        self.assertEqual(p.returncode, ERROR, p.stderr)

    def test_verdicts_pass_through(self):
        for code in (SHIP, GATE):
            with self.subTest(code=code):
                self.assertEqual(run_entrypoint("return %d" % code).returncode, code)


if __name__ == "__main__":
    unittest.main()
