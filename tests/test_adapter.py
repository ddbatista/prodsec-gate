"""prodsec-adapter: a deprecated alias of `prodsec-gate --json` that never gates."""
import unittest

from tests.support import ERROR, GATE, SHIP, VULNERABLE, run


class DeprecatedAlias(unittest.TestCase):

    def test_warns_and_names_the_replacement(self):
        p = run("mcp_adapter", VULNERABLE)
        self.assertIn("deprecated", p.stderr.lower())
        self.assertIn("prodsec-gate --json", p.stderr)

    def test_output_matches_gate_json(self):
        alias = run("mcp_adapter", VULNERABLE)
        gate = run("gate", VULNERABLE, "--json")
        self.assertTrue(alias.stdout.strip(), alias.stderr)
        self.assertEqual(alias.stdout, gate.stdout)

    def test_a_gate_worthy_dump_still_exits_0(self):
        # The adapter has no finding state: "manifest produced" is 0, even when
        # the gate would say GATE. Pipelines built on it must not start failing.
        self.assertEqual(run("gate", VULNERABLE).returncode, GATE)
        self.assertEqual(run("mcp_adapter", VULNERABLE).returncode, SHIP)

    def test_still_pipes_into_triage(self):
        manifest = run("mcp_adapter", VULNERABLE).stdout
        p = run("triage", "-", stdin=manifest)
        self.assertEqual(p.returncode, GATE, p.stderr)
        self.assertIn("VERDICT: GATE", p.stdout)

    def test_bad_input_is_not_audited(self):
        for stdin in ("", "not json", "[]"):
            with self.subTest(stdin=stdin):
                self.assertEqual(run("mcp_adapter", "-", stdin=stdin).returncode, ERROR)


if __name__ == "__main__":
    unittest.main()
