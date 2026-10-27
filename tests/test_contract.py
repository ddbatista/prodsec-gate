"""The exit-code contract, tested at the process boundary.

    0  pass       1  finding       2  not audited (bad input, nothing to audit, crash)

CI reads exit codes, not prose, so that is what these tests assert. Every row
runs a real command as a subprocess. See docs/design-notes.md once it exists;
until then the README's "Exit codes are the interface" section is the source.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLING = os.path.join(ROOT, "tooling")

SHIP, GATE, ERROR = 0, 1, 2


# The auditors read ~/.claude etc. Point HOME at an empty directory so a
# developer's real config can neither pass nor fail these tests.
EMPTY_HOME = tempfile.mkdtemp(prefix="prodsec-home-")


def tearDownModule():
    shutil.rmtree(EMPTY_HOME, ignore_errors=True)
MALFORMED = os.path.join("tests", "fixtures", "malformed-settings")
# Valid JSON with the wrong shape: crashes rule handling inside both auditors.
CRASHING = os.path.join("tests", "fixtures", "crashing-settings")


def run(script, *args, stdin=""):
    """Run tooling/<script>.py the way a CI job would; return the CompletedProcess."""
    env = dict(os.environ, HOME=EMPTY_HOME)
    return subprocess.run(
        [sys.executable, os.path.join(TOOLING, script + ".py")] + list(args),
        input=stdin, capture_output=True, text=True, cwd=ROOT, env=env, timeout=60)


def entry_point_modules():
    """Module names behind every console script in pyproject.toml.

    Parsed by hand: tomllib is 3.11+ and requires-python is >=3.9.
    """
    with open(os.path.join(ROOT, "pyproject.toml")) as f:
        text = f.read()
    section = text.split("[project.scripts]", 1)[1].split("\n[", 1)[0]
    return set(re.findall(r"prodsec_gate\.(\w+):main", section))


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

    ("gate", ["does-not-exist.json"], "", "does-not-exist.json"),
    ("gate", ["-"], "", "pipefail"),
    ("gate", ["-"], "not json", "not JSON"),
    ("gate", ["-"], '{"tools": []}', "no tools"),
    ("gate", ["-"], '{"agent": "x"}', "tools list"),
    ("gate", ["-"], '{"tools": [5]}', "internal error"),
    ("gate", ["-"], "5", "tools list"),
    ("gate", ["-", "--json"], "not json", "not JSON"),
    ("gate", ["-", "--json"], '{"tools": []}', "no tools"),

    ("mcp_adapter", ["does-not-exist.json"], "", "does-not-exist.json"),
    ("mcp_adapter", ["-"], "", "pipefail"),
    ("mcp_adapter", ["-"], "not json", "not JSON"),
    ("mcp_adapter", ["-"], "[]", "no tools"),
    ("mcp_adapter", ["-"], '{"agent": "x"}', "tools list"),
    ("mcp_adapter", ["-"], '{"tools": [5]}', "internal error"),

    ("maestro_score", ["does-not-exist.json", "--root", "."], "", "does-not-exist.json"),
    ("maestro_score", ["-", "--root", "."], "", "pipefail"),
    ("maestro_score", ["-", "--root", "."], "not json", "not JSON"),
    ("maestro_score", ["-", "--root", "."], "[]", "no findings"),
    ("maestro_score", ["-", "--root", "."], "[5]", "internal error"),

    # fetch has no input file; its "nothing to audit" is a server that never
    # answers tools/list. (Its REFUSED for --stdio without consent is a
    # deliberate refusal, not bad input, so it is not a row here.)
    ("mcp_fetch", ["--i-will-execute-this", "--stdio", sys.executable, "-c", "pass"],
     "", "no tools/list response"),

    # The auditors' input is a project directory and the settings inside it.
    # An EMPTY project is not a row: absent config is audited as Claude Code's
    # defaults, which is a real result.
    ("audit_agent_config", ["--project", "does-not-exist"], "", "does-not-exist"),
    ("audit_agent_config", ["--project", MALFORMED], "", "malformed"),
    ("audit_agent_config", ["--project", CRASHING], "", "internal error"),
    ("audit_allowlist", ["--project", "does-not-exist"], "", "does-not-exist"),
    ("audit_allowlist", ["--project", MALFORMED], "", "malformed"),
    ("audit_allowlist", ["--project", CRASHING], "", "internal error"),
    ("audit_allowlist", ["--project", "tests"], "", "no Claude Code settings"),
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


class ContractCoverage(unittest.TestCase):

    def test_every_console_script_has_rows(self):
        covered = {row[0] for row in NOT_AUDITED}
        missing = entry_point_modules() - covered
        self.assertFalse(missing, "console scripts with no NOT_AUDITED rows: %s"
                         % ", ".join(sorted(missing)))

    def test_entry_points_were_found(self):
        # Guard the guard: a parser that finds nothing would pass the test above.
        self.assertGreaterEqual(len(entry_point_modules()), 7)


class AuditContract(unittest.TestCase):

    def test_one_unreadable_file_is_reported_once(self):
        # --agent all reads the Claude scopes twice (settings, then the env
        # surface); the count must be of files, not of reads.
        p = run("audit_agent_config", "--project", MALFORMED, "--agent", "all")
        self.assertEqual(p.returncode, ERROR, p.stderr)
        self.assertIn("1 config file(s)", p.stderr)


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
