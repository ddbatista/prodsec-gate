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
import tempfile
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
    "t6": ({"untrusted_input", "private_data", "external_comms", "state_change"}, True),  # one false leg
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
        self.assertEqual(len(E.load_servers(MINI)), 5)

    def test_every_committed_server_is_valid(self):
        servers = E.load_servers(CORPUS)            # raises on any problem
        self.assertGreaterEqual(len(servers), 15)   # the spec's 15-25

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
        self.assertEqual(caps["untrusted_input"], {"tp": 2, "fp": 1, "fn": 0})
        self.assertEqual(caps["private_data"], {"tp": 3, "fp": 0, "fn": 0})
        self.assertEqual(caps["external_comms"], {"tp": 2, "fp": 0, "fn": 0})
        self.assertEqual(caps["state_change"], {"tp": 1, "fp": 1, "fn": 1})
        self.assertEqual(self.m["overall"], {"tp": 8, "fp": 2, "fn": 1})

    def test_gate_rate_on_acceptable_servers(self):
        # a, b, d and e are labelled SHIP; the fake detector gates a, b and e.
        self.assertEqual(self.m["gate_rate"], {"gated": 3, "acceptable": 4})

    def test_mismatches_are_classified(self):
        kinds = {m["server"]: m["kind"] for m in self.m["mismatches"]}
        # a: right legs would SHIP as expected, so the false leg is a detection bug.
        # b: the labelled legs already GATE, so SHIP is a policy question.
        # c: the missed state_change hid an irreversible action.
        # e: the labelled legs already GATE (policy) AND a leg was wrong.
        self.assertEqual(kinds, {"a-detection": "detection",
                                 "b-policy": "policy",
                                 "c-missed": "detection",
                                 "e-both": "both"})

    def test_policy_disputes_are_listed_even_when_detection_hides_them(self):
        # Wherever the labelled legs alone disagree with the expected verdict,
        # whatever the detector derived: a miss can make a dispute look settled.
        self.assertEqual(self.m["policy_disputes"], ["b-policy", "e-both"])

    def test_per_server_averages(self):
        # Overall recall per server: a 2/2, b 3/3, c 0/1, e 3/3; d has no legs
        # and is left out. Precision: a 2/3, b 3/3, e 3/4; c and d inferred
        # nothing and are left out.
        self.assertAlmostEqual(self.m["macro"]["overall"]["recall"], 3 / 4)
        self.assertAlmostEqual(self.m["macro"]["overall"]["precision"],
                               (2 / 3 + 1 + 3 / 4) / 3)

    def test_servers_labelled_gate_stay_gated(self):
        # Only c is labelled GATE, and the fake detector misses its state change.
        self.assertEqual(self.m["gate_recall"], {"gated": 0, "n": 1})

    def test_misses_name_the_tool(self):
        self.assertEqual(self.m["misses"], [("c-missed", "t4", ["state_change"])])


class ServerIntervals(unittest.TestCase):
    """Tools on one server share a writer and get missed together, so the
    unit of resampling is the server, not the tool."""

    def setUp(self):
        self.servers = E.load_servers(MINI)

    def interval(self, servers, seed=0):
        m = E.corpus_metrics(servers, infer=fake_infer)
        return E.server_interval(m["per_server"], "overall", E.recall, seed=seed)

    def test_collapses_when_every_server_scores_the_same(self):
        perfect = [fx for fx in self.servers if fx["server"] in ("a-detection", "b-policy", "e-both")]
        self.assertEqual(self.interval(perfect), (1.0, 1.0))

    def test_brackets_the_pooled_value_and_spans_the_server_spread(self):
        lo, hi = self.interval(self.servers)
        self.assertLessEqual(lo, 8 / 9)
        self.assertGreaterEqual(hi, 8 / 9)
        self.assertLess(lo, 0.8)        # c scores 0/1; resamples heavy in c pull it down
        self.assertEqual(hi, 1.0)       # resamples without c are perfect

    def test_is_reproducible(self):
        self.assertEqual(self.interval(self.servers, seed=7), self.interval(self.servers, seed=7))


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

    def test_servers_labelled_gate_never_drop_below_the_baseline(self):
        m = E.corpus_metrics(E.load_servers(CORPUS))
        base = json.load(open(BASELINE))["gate_recall"]
        self.assertGreaterEqual(
            m["gate_recall"]["gated"] / m["gate_recall"]["n"],
            base["gated"] / base["n"] - 1e-9,
            "fewer servers labelled GATE are gated than the baseline %d/%d"
            % (base["gated"], base["n"]))

    def test_baseline_was_measured_on_this_corpus(self):
        # Recall on a different corpus is a different number. A changed corpus
        # needs a regenerated baseline, reviewed as a diff, not a silent pass.
        self.assertEqual(
            json.load(open(BASELINE))["corpus_sha256"],
            E.fingerprint(E.load_servers(CORPUS)),
            "the corpus changed since the baseline was written; run "
            "eval_adapter.py --servers corpus/servers --write-baseline "
            "corpus/baseline.json and review the diff")

    def test_fingerprint_ignores_provenance_but_not_labels(self):
        servers = E.load_servers(MINI)
        before = E.fingerprint(servers)
        servers[0]["captured"] = "2030-01-01"
        self.assertEqual(E.fingerprint(servers), before)
        servers[0]["labels"]["t1"]["capabilities"] = []
        self.assertNotEqual(E.fingerprint(servers), before)

    def test_printed_floor_recall_is_the_committed_baseline(self):
        # The installed package does not ship corpus/, so the gate prints a
        # constant. It must say what the corpus measured, with its size.
        b = json.load(open(BASELINE))
        overall = b["floor_recall"]["overall"]
        self.assertEqual(E.A.FLOOR_RECALL, "%.1f%%" % (100 * overall["tp"] / overall["n"]))
        self.assertEqual(E.A.FLOOR_CORPUS, "%d servers, %d tools" % (b["servers"], b["tools"]))

    def test_baseline_covers_every_leg(self):
        baseline = json.load(open(BASELINE))["floor_recall"]
        self.assertEqual(set(baseline), set(E.A.CAP_VOCAB) | {"overall"})


class EvalCli(unittest.TestCase):

    def test_servers_mode_prints_the_report(self):
        p = run("eval_adapter", "--servers", MINI)
        self.assertEqual(p.returncode, 0, p.stderr)
        for heading in ("RECALL", "PRECISION", "GATE rate on acceptable servers",
                        "GATE recall on servers labelled GATE", "per server",
                        "bootstrap over servers", "MISMATCH"):
            self.assertIn(heading, p.stdout)

    def test_servers_mode_rejects_an_invalid_corpus(self):
        with tempfile.TemporaryDirectory() as d:
            fx = json.load(open(os.path.join(MINI, "a-detection.json")))
            fx["licence"] = "GPL-3.0"
            json.dump(fx, open(os.path.join(d, "bad.json"), "w"))
            p = run("eval_adapter", "--servers", d)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("GPL-3.0", p.stderr)

    def test_write_baseline_needs_servers(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "baseline.json")
            p = run("eval_adapter", "--write-baseline", out)
            self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
            self.assertFalse(os.path.exists(out))


if __name__ == "__main__":
    unittest.main()
