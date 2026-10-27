"""The classifier signal layer's safety properties, with fake backends.

A backend is any (system, payload) -> text callable, so every property here is
checked offline: no test in this file makes a network call.

    union only   a classifier can ADD a leg, never remove one
    fail closed  raising, junk or an empty reply means "did not run"
"""
import importlib.util
import json
import os
import sys
import unittest

from tests.test_contract import ERROR, GATE, ROOT, TOOLING
from tests.test_gate import HARMLESS, gate_in_process

sys.path.insert(0, TOOLING)
import mcp_adapter as A  # noqa: E402

# Keywords alone give this tool all four capabilities.
LOUD = {"name": "fetch_and_send",
        "description": "Fetch a web page, read the customer database, "
                       "then send an email and delete the record."}
# Keywords give this one nothing.
QUIET = {"name": "relay_to_partner",
         "description": "Forwards the selected record to our partner endpoint.",
         "annotations": {"openWorldHint": False}}


def raises(system, payload):
    raise RuntimeError("network down")


def says(text):
    return lambda system, payload: text


class UnionOnly(unittest.TestCase):

    def test_a_downgrading_classifier_never_removes_a_leg(self):
        keyword_caps, _, _ = A.infer(LOUD)
        for reply in ("none", "untrusted_input", "private_data"):
            with self.subTest(reply=reply):
                caps, _, notes, ok = A.infer_signalled(LOUD, says(reply))
                self.assertTrue(ok)
                self.assertTrue(keyword_caps <= caps, caps)

    def test_an_adding_classifier_adds_the_leg_and_says_so(self):
        caps, _, notes, ok = A.infer_signalled(QUIET, says("external_comms"))
        self.assertTrue(ok)
        self.assertIn("external_comms", caps)
        self.assertTrue(any("ADDED external_comms" in n for n in notes), notes)

    def test_none_is_a_real_answer(self):
        caps, _, _, ok = A.infer_signalled(QUIET, says("none"))
        self.assertTrue(ok)
        self.assertEqual(caps, A.infer(QUIET)[0])


class FailClosed(unittest.TestCase):

    def test_non_runs_are_reported_as_non_runs(self):
        for label, backend in (("raises", raises),
                               ("junk", says("I cannot help with that.")),
                               ("empty", says("")),
                               ("whitespace", says("  \n ")),
                               ("None", says(None))):
            with self.subTest(backend=label):
                caps, _, notes, ok = A.infer_signalled(QUIET, backend)
                self.assertFalse(ok)
                self.assertTrue(any("FAIL-CLOSED" in n for n in notes), notes)

    def test_out_of_vocabulary_words_never_reach_the_manifest(self):
        caps, _, _, _ = A.infer_signalled(QUIET, says("external_comms\nrm -rf /\nadmin"))
        self.assertTrue(caps <= set(A.CAP_VOCAB), caps)


class GateFailedClosedSplit(unittest.TestCase):

    def test_every_tool_failing_closed_is_an_instrument_failure(self):
        rc, _ = gate_in_process([HARMLESS], backend=raises)
        self.assertEqual(rc, ERROR)

    def test_some_tools_failing_closed_is_a_gate(self):
        def fails_on_get_time(system, payload):
            if "get_time" in payload:
                raise RuntimeError("timeout")
            return "none"

        rc, out = gate_in_process([HARMLESS, "--json"], backend=fails_on_get_time)
        self.assertEqual(rc, GATE)
        self.assertEqual(json.loads(out)["instrument"]["failed_closed"], ["get_time"])


@unittest.skipUnless(importlib.util.find_spec("claude_agent_sdk"),
                     "the [live] extra (claude-agent-sdk) is not installed")
class AgentSdkLockdown(unittest.TestCase):

    def test_self_check_passes(self):
        # Builds the options and inspects them; sends nothing.
        import agent_sdk_backend as asb
        self.assertTrue(asb.self_check())


if __name__ == "__main__":
    unittest.main()
