#!/usr/bin/env python3
"""
maestro_score.py — score a MAESTRO pass by checking its citations.

The L15 protocol says: constrain the agent's output until being wrong is
detectable, then SAMPLE AND SCORE. Everyone does the first half, because it is
one paste. Nobody does the second half, because it is ten manual greps.

This is the ten greps. Requirement 1 of the protocol -- `file.py:LINE`, quoted
-- exists precisely because it is mechanically checkable, and this module is
the machine that checks it.

WHAT IT CAN DECIDE, AND WHAT IT CANNOT
--------------------------------------
Three buckets were specified in reference/maestro-pass.html: REAL, MISCITED,
FABRICATED. A citation checker can only reach the FABRICATED boundary:

    FABRICATED   the file, the line, or the quoted text does not exist
    MISPLACED    the quote exists in the file, but not at the cited line
    CITED        the line exists and says what was quoted

CITED IS NOT "REAL". "The line exists and says that" and "the failure scenario
would actually occur" are different claims, and only the first is greppable.
The dangerous bucket -- MISCITED, where the concern is reasonable and the line
does not support it -- lives INSIDE the CITED pile and needs a human. This tool
prints that limit on every run rather than leaving it in the docs, for the same
reason gate.py prints its INSTRUMENT block: a verdict must carry its instrument.

INPUT: JSON list (or {"findings": [...]}) of objects with:
    layer     1-7
    title     short claim
    file      repo-relative path
    line      1-based line number
    quote     the text expected at that line
    scenario  concrete input -> concrete wrong outcome
    falsifier what you would observe if this were NOT real
A finding missing any required field is DROPPED, not fixed -- that is the
protocol, not a convenience.

EXIT: 0 every citation checks out · 1 fabricated/misplaced/dropped present
      2 nothing was scored (a configuration failure, not a clean pass)
"""
import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _cli                      # noqa: E402

REQUIRED = ("layer", "title", "file", "line", "quote", "scenario", "falsifier")
LAYERS = {
    1: "Foundation Models",
    2: "Data Operations",
    3: "Agent Frameworks",
    4: "Deployment & Infrastructure",
    5: "Evaluation & Observability",
    6: "Security & Compliance",
    7: "Agent Ecosystem",
}
OK, FINDINGS_BAD = _cli.SHIP, _cli.GATE


def norm(s):
    """Whitespace-insensitive compare. Indentation is not a citation error."""
    return re.sub(r"\s+", " ", (s or "")).strip()


def check(f, root):
    """-> (bucket, detail). Pure: no output, so the tests can call it.

    `status: "fixed"` inverts the test. Found 2026-09-23 by fixing three real
    findings and re-scoring the pass that raised them: their quoted lines were
    gone, so the scorer called them FABRICATED -- reporting remediated work as
    invented. A quote that has DISAPPEARED from a file you claim to have fixed
    is evidence the fix landed; a quote still sitting there is evidence it did
    not. So a finding marked fixed is checked the other way round.
    """
    missing = [k for k in REQUIRED if not str(f.get(k, "")).strip()]
    if missing:
        return "DROPPED", "missing required field(s): " + ", ".join(missing)

    path = os.path.join(root, f["file"])
    if not os.path.isfile(path):
        return "FABRICATED", "no such file: %s" % f["file"]

    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = fh.read().splitlines()

    try:
        n = int(f["line"])
    except (TypeError, ValueError):
        return "DROPPED", "line is not a number: %r" % (f["line"],)

    q = norm(f["quote"])
    fixed = str(f.get("status", "")).lower() == "fixed"
    if fixed:
        # Preferred evidence: the line the FIX added. Required whenever the fix
        # is an addition rather than a deletion -- F4 of pass 0002 was fixed by
        # clearing a global at the top of the function, so its cited line (the
        # return that failed to clear it) correctly still exists. Judging
        # remediation by the absence of the old line marked that as UNFIXED.
        fq = norm(f.get("fix_quote", ""))
        if fq:
            if any(fq in norm(L) for L in lines):
                return "RESOLVED", ("fix_quote found in %s" % f["file"])
            return "UNFIXED", ("marked fixed, but fix_quote is not in %s"
                               % f["file"])
        still_there = any(q and q in norm(L) for L in lines)
        if still_there:
            return "UNFIXED", ("marked fixed, but the cited line is still in %s "
                               "-- if the fix was an ADDITION, give a fix_quote"
                               % f["file"])
        return "RESOLVED", ("quote is gone from %s -- consistent with the "
                            "recorded fix" % f["file"])

    if not 1 <= n <= len(lines):
        where = [i for i, L in enumerate(lines, 1) if q and q in norm(L)]
        if where:
            return "MISPLACED", ("line %d is past EOF (%d lines); the quote is at %s"
                                 % (n, len(lines), ", ".join(map(str, where[:3]))))
        return "FABRICATED", "line %d does not exist (%d lines) and the quote is not in the file" % (n, len(lines))

    if q and q in norm(lines[n - 1]):
        return "CITED", "%s:%d" % (f["file"], n)

    where = [i for i, L in enumerate(lines, 1) if q and q in norm(L)]
    if where:
        return "MISPLACED", ("cited %d, actually at %s"
                             % (n, ", ".join(map(str, where[:3]))))
    return "FABRICATED", ("line %d exists but does not contain the quote, and the "
                          "quote appears nowhere in the file -- it was invented, OR "
                          'the code changed since (mark it "status": "fixed")' % n)



SELF_TEST_FILE = """line one
def widen(): return mint(x)   # the quoted line
line three
"""


def self_test():
    """Permanent fixtures for every bucket.

    These began as one-off files in /tmp while writing the docs, which is the
    recurring flaw this repo has named twice: a claim whose supporting run no
    longer exists. Now they run on demand and in CI.
    """
    import tempfile
    ok = True
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "t.py"), "w") as fh:
            fh.write(SELF_TEST_FILE)
        base = {"layer": 3, "title": "t", "scenario": "a -> b", "falsifier": "c"}
        cases = [
            ("exact hit",            dict(base, file="t.py", line=2,
                                          quote="def widen(): return mint(x)"), "CITED"),
            ("indentation ignored",  dict(base, file="t.py", line=2,
                                          quote="   def widen():   return mint(x)  "), "CITED"),
            ("stale line number",    dict(base, file="t.py", line=1,
                                          quote="def widen(): return mint(x)"), "MISPLACED"),
            ("line past EOF",        dict(base, file="t.py", line=99,
                                          quote="def widen(): return mint(x)"), "MISPLACED"),
            ("quote not in file",    dict(base, file="t.py", line=2,
                                          quote="os.system(user_input)"), "FABRICATED"),
            ("no such file",         dict(base, file="nope.py", line=1,
                                          quote="anything"), "FABRICATED"),
            ("missing falsifier",    {k: v for k, v in dict(base, file="t.py", line=2,
                                      quote="line one").items() if k != "falsifier"}, "DROPPED"),
            ("line not a number",    dict(base, file="t.py", line="two",
                                          quote="line one"), "DROPPED"),
            ("fixed, quote gone",    dict(base, file="t.py", line=2, status="fixed",
                                          quote="os.system(user_input)"), "RESOLVED"),
            ("fixed, quote remains", dict(base, file="t.py", line=2, status="fixed",
                                          quote="def widen(): return mint(x)"), "UNFIXED"),
            ("fixed by addition",    dict(base, file="t.py", line=2, status="fixed",
                                          quote="def widen(): return mint(x)",
                                          fix_quote="line three"), "RESOLVED"),
            ("fix_quote absent",     dict(base, file="t.py", line=2, status="fixed",
                                          quote="def widen(): return mint(x)",
                                          fix_quote="not in this file"), "UNFIXED"),
        ]
        for name, finding, expect in cases:
            got, detail = check(finding, d)
            good = got == expect
            ok = ok and good
            print("  %-22s %-11s %s" % (name, got, "PASS" if good else
                                        "FAIL (expected %s)" % expect))
    print("  %d/%d" % (sum(1 for _ in cases), len(cases)) if ok else "  FAILURES")
    return ok


def load(path):
    d = _cli.read_json(path)
    return d["findings"] if isinstance(d, dict) and "findings" in d else d


@_cli.entrypoint
def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="prodsec-maestro",
        description="Score a MAESTRO pass by checking whether its citations exist.")
    # nargs="?" because --prompt takes no input. Found 2026-09-22 by installing
    # the package and running the documented command: `prodsec-maestro --prompt`
    # exited 2 with "the following arguments are required: findings". Third time
    # packaging or documenting has found a defect that using it never did.
    ap.add_argument("findings", nargs="?", help="findings JSON, or - for stdin")
    ap.add_argument("--root", default=".", help="repo root the citations are relative to")
    ap.add_argument("--prompt", action="store_true",
                    help="print the constrained MAESTRO prompt and exit")
    ap.add_argument("--self-test", action="store_true",
                    help="run the bucket fixtures and exit")
    a = ap.parse_args(argv)

    if a.prompt:
        print(PROMPT)
        return OK

    if getattr(a, "self_test", False):
        print("maestro_score — bucket fixtures")
        return OK if self_test() else FINDINGS_BAD

    if not a.findings:
        ap.error("a findings file is required (or - for stdin); "
                 "use --prompt to print the pass prompt instead")

    findings = load(a.findings)
    if not isinstance(findings, list) or not findings:
        raise _cli.NotAudited(
            "no findings in the input. Nothing was scored, so this is a\n"
            "       configuration failure, not a clean pass.")

    buckets = {"CITED": [], "MISPLACED": [], "FABRICATED": [], "DROPPED": [],
               "RESOLVED": [], "UNFIXED": []}
    seen_layers = set()
    print("=" * 68)
    print(" MAESTRO CITATION SCORE  ·  %d finding(s)" % len(findings))
    print("=" * 68)
    for i, f in enumerate(findings, 1):
        bucket, detail = check(f, a.root)
        buckets[bucket].append((i, f, detail))
        if bucket != "DROPPED":
            try:
                seen_layers.add(int(f.get("layer", 0)))
            except (TypeError, ValueError):
                pass
        mark = {"CITED": " ok ", "MISPLACED": "MOVE", "FABRICATED": "FAB!",
                "DROPPED": "DROP", "RESOLVED": "FIXD", "UNFIXED": "!!!!"}[bucket]
        print(" [%s] %2d. L%-2s %s" % (mark, i, f.get("layer", "?"),
                                       str(f.get("title", "?"))[:44]))
        print("        %s" % detail)

    print("-" * 68)
    n = len(findings)
    for b in ("CITED", "MISPLACED", "FABRICATED", "DROPPED", "RESOLVED", "UNFIXED"):
        print("  %-11s %2d / %2d" % (b, len(buckets[b]), n))

    # The number that says whether the pass was HALLUCINATED, as opposed to
    # merely stale. Found the first time this was run (2026-09-21): 9 of 10
    # line numbers were wrong and 10 of 10 quotes were real, because the file
    # had been edited an hour earlier. A checker that only compared line
    # numbers would have reported 90% fabrication against a pass in which
    # nothing was invented. The quote is the anchor; the line number is a hint.
    quotes_ok = len(buckets["CITED"]) + len(buckets["MISPLACED"])
    scored = quotes_ok + len(buckets["FABRICATED"])
    if scored:
        print("-" * 68)
        print("  quotes that exist in the cited file:  %d / %d" % (quotes_ok, scored))
        print("  ^ the anti-hallucination number. Line numbers drift with every")
        print("    edit; invented text does not appear in a file by accident.")

    # The tell from L15: real systems have empty layers. A pass with all seven
    # populated has generated rather than observed -- so say which are empty.
    empty = sorted(set(LAYERS) - seen_layers)
    print("-" * 68)
    print(" LAYER COVERAGE")
    if empty:
        print("  EMPTY: " + ", ".join("L%d %s" % (i, LAYERS[i]) for i in empty))
        print("  Good. An empty layer is a finding you can point at.")
    else:
        print("  All seven layers populated. That is the tell -- real systems")
        print("  have empty cells. Check that each layer was OBSERVED, not filled.")

    print("-" * 68)
    print(" INSTRUMENT")
    print("  checked: file exists · line exists · line contains the quote")
    print("  NOT checked: whether the failure scenario would actually occur.")
    print("  CITED is not REAL. MISCITED -- reasonable concern, line does not")
    print("  support it -- is inside the CITED pile and needs a human. That is")
    print("  the dangerous bucket, because it reads as real.")
    print("  Sample the CITED pile by hand. This tool bought you the cheap half.")
    print("=" * 68)

    bad = (len(buckets["FABRICATED"]) + len(buckets["MISPLACED"])
           + len(buckets["DROPPED"]) + len(buckets["UNFIXED"]))
    return FINDINGS_BAD if bad else OK


PROMPT = """\
Threat-model this repo using MAESTRO's seven layers:
  1 Foundation Models   2 Data Operations   3 Agent Frameworks
  4 Deployment & Infrastructure   5 Evaluation & Observability
  6 Security & Compliance (vertical)   7 Agent Ecosystem
Scope: <PATHS>

RULES -- a finding that breaks any of these is dropped, not fixed:
- Cite file.py:LINE. Quote the line verbatim. If you cannot, do not raise it.
- State a failure scenario: concrete input -> concrete wrong outcome.
- State what you would observe if this were NOT real.
- If a layer has nothing in this repo, write EMPTY. Do not fill it.
- Then list cross-layer threats: name both layers and the path between them.
Rank by exploitability, not by severity words.

Output ONLY a JSON array, one object per finding:
  {"layer": 3, "title": "...", "file": "tooling/x.py", "line": 42,
   "quote": "the line, verbatim", "scenario": "input -> wrong outcome",
   "falsifier": "what you would see if this were not real"}
Cross-layer findings use "layer": "cross" and name both layers in the title."""


if __name__ == "__main__":
    sys.exit(main())
