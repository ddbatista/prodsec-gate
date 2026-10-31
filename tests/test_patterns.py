"""The keyword floor on descriptions OUTSIDE the corpus.

The patterns are tuned against corpus/servers, so the corpus cannot show
overfitting. These descriptions come from server kinds the corpus does not
have (calendars, vaults, CI, weather, translation), written to the labelling
rules in corpus/README.md. Each pins a leg a tuning pass once gained or lost
by accident. openWorldHint is set false so only the words are tested.
"""
import sys
import unittest

from tests.support import TOOLING

sys.path.insert(0, TOOLING)
import mcp_adapter as A  # noqa: E402


def legs(name, description, **annotations):
    annotations.setdefault("openWorldHint", False)
    caps, _, _ = A.infer({"name": name, "description": description,
                          "annotations": annotations})
    return caps


# (name, description, leg, expected): the leg must (or must not) be inferred.
CASES = [
    # true legs the floor must keep
    ("http_request", "Send an HTTP request to a URL and return the response body.",
     "untrusted_input", True),
    ("update_event", "Modify an existing calendar event.", "state_change", True),
    ("get_license", "Retrieve the stored license key for a product.", "private_data", True),
    ("vault_get", "Return the encryption key for a vault entry.", "private_data", True),
    ("create_issues", "Create issues in bulk from a list.", "external_comms", True),
    # false legs the floor must not add
    ("get_pr", "Get a pull request with its created_at date and review status.",
     "external_comms", False),
    ("tracker_info", "Returns the address of the issue tracker.", "external_comms", False),
    ("summarise", "Use OpenAI to summarise a code review.", "external_comms", False),
    ("is_fork", "Check whether a repository is a fork of another.", "state_change", False),
    ("diff_staged", "Shows changes that are staged for commit.", "state_change", False),
    ("monitor_get", "Retrieve one monitor. This does not run or modify the monitor.",
     "state_change", False),
    ("list_pipelines", "List pipelines; results are returned in pages of 50.",
     "untrusted_input", False),
    ("translate", "Translate text between languages. Preserves paragraph blocks.",
     "untrusted_input", False),
    ("forecast", "Five-day forecast for a city. Data source: OpenWeatherMap.",
     "untrusted_input", False),
]


class OutOfCorpus(unittest.TestCase):

    def test_each_case(self):
        for name, description, leg, expected in CASES:
            with self.subTest(tool=name, leg=leg):
                got = legs(name, description)
                self.assertEqual(leg in got, expected,
                                 "%s: %r -> %s" % (name, description, sorted(got)))

    def test_a_publish_phrase_does_not_hide_untrusted_content(self):
        # The diff of a merge request is content others wrote. Reading it is
        # not egress, and a false egress leg would also switch off the
        # openWorldHint nudge (absent hint, so the default applies here).
        caps, _, _ = A.infer({"name": "get_mr_diff",
                              "description": "Return the diff of an opened merge request."})
        self.assertIn("untrusted_input", caps)
        self.assertNotIn("external_comms", caps)


if __name__ == "__main__":
    unittest.main()
