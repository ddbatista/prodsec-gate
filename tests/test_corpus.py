"""The real-server corpus: fixture schema, eval metrics and the recall ratchet.

Metrics are checked against a synthetic mini-corpus with an injected detector,
so the expected numbers below are worked out by hand from the fixtures, not
from the keyword patterns (which #14 is allowed to change). The ratchet runs
the real keyword floor over the committed corpus.
"""
import glob
import json
import os
import sys
import unittest

from tests.support import ROOT, TOOLING, run

sys.path.insert(0, TOOLING)
import eval_adapter as E  # noqa: E402

MINI = os.path.join(ROOT, "tests", "fixtures", "corpus-mini")
CORPUS = os.path.join(ROOT, "corpus", "servers")
BASELINE = os.path.join(ROOT, "corpus", "baseline.json")

# What the fake detector "sees" in each mini-corpus tool: (capabilities, reversible).
FAKE = {
    "t1": ({"private_data"}, None),                                   # right
    "t2": ({"state_change", "untrusted_input"}, True),                # one false leg
    "t3": ({"untrusted_input", "private_data", "external_comms"}, None),  # right
    "t4": (set(), None),                                              # misses state_change
    "t5": (set(), None),                                              # right
}


def fake_infer(tool):
    caps, rev = FAKE[tool["name"]]
    return set(caps), rev, []


def fixture(**over):
    fx = json.load(open(os.path.join(MINI, "a-detection.json")))
    fx.update(over)
    return fx


class Schema(unittest.TestCase):

    def test_mini_corpus_is_valid(self):
        self.assertEqual(len(E.load_servers(MINI)), 4)

    def test_every_committed_server_is_valid(self):
        servers = E.load_servers(CORPUS)            # raises on any problem
        self.assertGreaterEqual(len(servers), 3)

    def test_rejects_missing_provenance(self):
        for field in ("package", "version", "captured", "capture_method", "licence", "source"):
            with self.subTest(field=field):
                fx = fixture()
                del fx[field]
                self.assertTrue(E.problems(fx))

    def test_rejects_non_permissive_licence(self):
        for licence in ("GPL-3.0", "AGPL-3.0-only", "proprietary", "UNLICENSED", ""):
            with self.subTest(licence=licence):
                self.assertTrue(E.problems(fixture(licence=licence)))

    def test_accepts_permissive_licences(self):
        for licence in ("MIT", "Apache-2.0", "BSD-3-Clause", "ISC"):
            with self.subTest(licence=licence):
                self.assertEqual(E.problems(fixture(licence=licence)), [])

    def test_licence_expressions_need_every_part_permissive(self):
        self.assertEqual(E.problems(fixture(licence="MIT AND Apache-2.0")), [])
        self.assertEqual(E.problems(fixture(licence="(MIT OR Apache-2.0)")), [])
        self.assertTrue(E.problems(fixture(licence="MIT AND GPL-3.0")))
        self.assertTrue(E.problems(fixture(licence="MIT OR GPL-3.0")))

    def test_rejects_unknown_capture_method(self):
        self.assertTrue(E.problems(fixture(capture_method="npx on my laptop")))

    def test_every_tool_needs_exactly_one_label(self):
        fx = fixture()
        del fx["labels"]["t2"]
        self.assertTrue(E.problems(fx), "unlabelled tool")
        fx = fixture()
        fx["labels"]["ghost"] = {"capabilities": [], "reversible": None, "why": "x"}
        self.assertTrue(E.problems(fx), "label for a tool that was not captured")

    def test_label_rules(self):
        bad = [
            {"capabilities": ["exfiltration"], "reversible": None, "why": "x"},   # not a leg
            {"capabilities": ["state_change"], "reversible": None, "why": "x"},   # needs a bool
            {"capabilities": ["private_data"], "reversible": True, "why": "x"},   # only for state_change
            {"capabilities": [], "reversible": None, "why": ""},                  # no reason
        ]
        for label in bad:
            with self.subTest(label=label):
                fx = fixture()
                fx["labels"]["t1"] = label
                self.assertTrue(E.problems(fx))

    def test_expected_verdict_needs_a_rationale(self):
        self.assertTrue(E.problems(fixture(expected_verdict="MAYBE")))
        self.assertTrue(E.problems(fixture(rationale="")))


class Metrics(unittest.TestCase):

    def setUp(self):
        self.m = E.corpus_metrics(E.load_servers(MINI), infer=fake_infer)

    def test_per_leg_counts(self):
        caps = self.m["capabilities"]
        self.assertEqual(caps["untrusted_input"], {"tp": 1, "fp": 1, "fn": 0})
        self.assertEqual(caps["private_data"], {"tp": 2, "fp": 0, "fn": 0})
        self.assertEqual(caps["external_comms"], {"tp": 1, "fp": 0, "fn": 0})
        self.assertEqual(caps["state_change"], {"tp": 1, "fp": 0, "fn": 1})
        self.assertEqual(self.m["overall"], {"tp": 5, "fp": 1, "fn": 1})

    def test_gate_rate_on_acceptable_servers(self):
        # a, b and d are labelled SHIP; the fake detector gates a and b.
        self.assertEqual(self.m["gate_rate"], {"gated": 2, "acceptable": 3})

    def test_mismatches_are_classified(self):
        kinds = {m["server"]: m["kind"] for m in self.m["mismatches"]}
        # a: right legs would SHIP as expected, so the false leg is a detection bug.
        # b: the labelled legs already GATE, so SHIP is a policy question.
        # c: the missed state_change hid an irreversible action.
        self.assertEqual(kinds, {"a-detection": "detection",
                                 "b-policy": "policy",
                                 "c-missed": "detection"})

    def test_misses_name_the_tool(self):
        self.assertEqual(self.m["misses"], [("c-missed", "t4", ["state_change"])])


class Ratchet(unittest.TestCase):

    def test_floor_recall_never_drops_below_the_baseline(self):
        m = E.corpus_metrics(E.load_servers(CORPUS))
        baseline = json.load(open(BASELINE))["floor_recall"]
        for leg, base in baseline.items():
            with self.subTest(leg=leg):
                got = m["overall"] if leg == "overall" else m["capabilities"][leg]
                floor = base["tp"] / base["n"] if base["n"] else 0.0
                self.assertGreaterEqual(
                    E.recall(got), floor - 1e-9,
                    "recall on %s dropped below the committed baseline %d/%d; "
                    "a pattern change may not buy precision with missed GATEs"
                    % (leg, base["tp"], base["n"]))

    def test_baseline_covers_every_leg(self):
        baseline = json.load(open(BASELINE))["floor_recall"]
        self.assertEqual(set(baseline), set(E.A.CAP_VOCAB) | {"overall"})


class EvalCli(unittest.TestCase):

    def test_servers_mode_prints_the_report(self):
        p = run("eval_adapter", "--servers", MINI)
        self.assertEqual(p.returncode, 0, p.stderr)
        for heading in ("recall", "precision", "GATE rate on acceptable servers",
                        "MISMATCH"):
            self.assertIn(heading, p.stdout)

    def test_servers_mode_rejects_an_invalid_corpus(self):
        p = run("eval_adapter", "--servers", os.path.join(ROOT, "tests", "fixtures"))
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)


if __name__ == "__main__":
    unittest.main()
