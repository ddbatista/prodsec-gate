"""Which files the pre-commit hook hands to prodsec-gate.

pre-commit matches `files:` with re.search against each repo-relative path.
The pattern is read from the hook definition, not copied here, so the test
cannot drift from what consumers actually run.
"""
import os
import re
import unittest

from tests.test_contract import ROOT


def hook_pattern():
    with open(os.path.join(ROOT, ".pre-commit-hooks.yaml")) as f:
        m = re.search(r"^\s*files:\s*'([^']*)'\s*$", f.read(), re.M)
    return re.compile(m.group(1))


MUST_MATCH = [
    "server.tools.json",
    "vendor/github.tools.json",
    "mcp-dump.json",                 # *dump*.json keeps working
    "dumps/slack-dump.json",
]
MUST_NOT_MATCH = [
    ".mcp.json",                     # a Claude Code server CONFIG, not a dump
    "config/.mcp.json",
    "package.json",
    "tools.json",                    # no name before .tools.json
    "server.tools.json.bak",
]


class HookPattern(unittest.TestCase):

    def test_matches_dumps(self):
        p = hook_pattern()
        for path in MUST_MATCH:
            with self.subTest(path=path):
                self.assertTrue(p.search(path))

    def test_ignores_configs_and_other_json(self):
        p = hook_pattern()
        for path in MUST_NOT_MATCH:
            with self.subTest(path=path):
                self.assertFalse(p.search(path))


if __name__ == "__main__":
    unittest.main()
