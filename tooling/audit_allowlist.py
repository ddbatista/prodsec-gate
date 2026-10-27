#!/usr/bin/env python3
"""
audit_allowlist.py — L12: grade the allowlist you never sat down and wrote.

An `allow` list built by clicking "Yes, don't ask again" is a POLICY DERIVED FROM
BEHAVIOUR. Nobody reviewed it; it accreted one convenience decision at a time,
each one made while thinking about the task rather than the blast radius. This
script reads it back to you sorted by how much a rule actually permits.

THE ONE IDEA:

    blast radius is not a function of how specific the pattern looks.

    Bash(python3 -c ' *)   obviously broad — a wildcard on an interpreter
    Bash(python3 -)        looks narrow, no wildcard at all, and permits
                           ARBITRARY CODE: the program arrives on stdin, so it
                           is not in the command string the rule matches.

The second is the dangerous one, and it is the one a specificity-based reviewer
(human or script) waves through. So the classification here is by WHAT CAN RUN,
not by pattern shape.

TWO HEURISTIC FAILURES FOUND WHILE WRITING THIS, both left visible in the code:
  * v1 bucketed by "does the spec contain a wildcard". It filed `Bash(python3 -)`
    as narrow. That is the exact mistake the tool exists to catch, made by the
    tool. Fixed by matching stdin-program FORMS, not wildcards.
  * v2's stdin regex `\\s-\\s*$` flagged `Bash(python3 triage.py -)`, where the
    dash feeds DATA to a named script, not code to an interpreter. Over-flagging.
    Fixed by requiring the dash to be the interpreter's own argument. The test
    corpus below keeps both cases so the failure cannot silently return.

MODE INTERACTION — the part that matters if you just pinned your mode:
  Entering auto mode DROPS broad execution allow rules (blanket `Bash(*)`,
  "wildcarded interpreters like Bash(python*)", package-manager run commands,
  `Agent` rules) and "narrow rules carry over". Dropped rules are RESTORED when
  you leave auto mode. So:
    - a wildcarded interpreter rule is neutralised in auto, live everywhere else
    - a narrow-LOOKING unbounded rule (`python3 -`) is expected to carry over
      into auto mode too — inference from "narrow rules carry over", NOT stated
      for this case. It is a run-book item, printed as one.
  Verified 2026-08-19: https://code.claude.com/docs/en/permission-modes

USAGE
  python3 audit_allowlist.py [--project DIR] [--self-test]
Exit 0 = no unbounded rules, 1 = at least one, 2 = not audited (no settings in
any scope, an unreadable --project, or a settings file that cannot be parsed).
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _cli                      # noqa: E402

HOME = Path.home()
SCOPES = [
    ("user",    HOME / ".claude" / "settings.json"),
    ("project", Path(".claude") / "settings.json"),
    ("local",   Path(".claude") / "settings.local.json"),
    ("managed", Path("/Library/Application Support/ClaudeCode/managed-settings.json")),
]

INTERPRETERS = r"python3?|perl|ruby|node|osascript|bash|sh|zsh|awk"
PKG_RUN = r"\b(npm|pnpm|yarn|bun|npx|pip3?|uv|cargo|go|make|gradle|mvn)\b\s+(run|exec|install|test|x)?"

# Forms where the PROGRAM IS NOT IN THE COMMAND STRING. These are unbounded no
# matter how exact the rest of the pattern looks.
UNBOUNDED_FORMS = [
    # interpreter reading its program from stdin: `python3 -`, `sh -`
    (r"\b(?:%s)\b(?:\s+-[A-Za-z]+)*\s+-\s*$" % INTERPRETERS,
     "interpreter reads its program from STDIN — nothing in the rule bounds it"),
    # interpreter -c/-e with a wildcard: the code is whatever the model writes
    (r"\b(?:%s)\b.*\s-(?:c|e)\b.*\*" % INTERPRETERS,
     "wildcard on -c/-e: the code itself is the wildcard"),
    # piping anything into an interpreter
    (r"\|\s*(?:%s)\b" % INTERPRETERS,
     "pipes into an interpreter — the program is produced at run time"),
    # bare interpreter, no script named
    (r"^\s*(?:%s)\s*$" % INTERPRETERS,
     "bare interpreter with no script — reads a program from stdin or REPL"),
    # eval / exec of a built string
    (r"\beval\b|\bexec\b",
     "eval/exec of a string built at run time"),
    # a wildcard where the command itself goes
    (r"^\s*\*", "wildcard in the command position — matches any binary"),
]


def load(path):
    """The settings at path, or None if the file does not exist.

    A file that exists but cannot be read or parsed is NOT absent: treating it
    as absent audits the other scopes and reports on rules it never saw.
    """
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as e:
        raise _cli.NotAudited("malformed JSON in %s: %s" % (path, e))
    except OSError as e:
        raise _cli.NotAudited("cannot read %s: %s" % (path, e))


def parse(rule):
    m = re.match(r"^\s*([A-Za-z_][\w]*)\s*\((.*)\)\s*$", str(rule))
    return (m.group(1), m.group(2).strip()) if m else (str(rule).strip(), None)


def classify(rule):
    """(grade, why). grade in UNBOUNDED / BLANKET / BROAD / NARROW / NON-BASH."""
    tool, spec = parse(rule)
    if tool != "Bash":
        if spec is None:
            # A whole tool pre-approved. Real scope creep, but NOT code execution
            # unless the tool is a shell — graded separately so the headline
            # count stays honest.
            return "WHOLE-TOOL", ("every use of %s is pre-approved, unscoped. "
                                  "Not code execution; still an unreviewed grant." % tool)
        return "NON-BASH", ""
    if spec is None or spec in ("*", "**"):
        return "BLANKET", "all shell commands are pre-approved"

    for pattern, why in UNBOUNDED_FORMS:
        if re.search(pattern, spec, re.I):
            return "UNBOUNDED", why

    if re.search(r"\b(?:%s)\b" % INTERPRETERS, spec) and "*" in spec:
        return "BROAD", "wildcarded interpreter — auto mode drops this one; live in every other mode"
    if re.search(PKG_RUN, spec) and "*" in spec:
        return "BROAD", "wildcarded package-manager command — arbitrary scripts from the manifest"
    if "*" in spec:
        return "BROAD", "wildcard argument: bounded binary, unbounded arguments"
    return "NARROW", ""


def dead(spec, root):
    """Does the rule name a path that no longer exists? (cruft, not danger)"""
    if not spec:
        return None
    for tok in re.findall(r"[\w./-]+\.(?:py|json|html|md|yaml|toml|txt)", spec):
        if not (root / tok).exists() and not any((root / d / tok).exists()
                                                 for d in ("tooling", "harness", "lessons")):
            return tok
    return None


# --------------------------------------------------------------------------
SELF_TEST = [
    # rule,                                   expected grade
    ("Bash(python3 -)",                        "UNBOUNDED"),   # v1 got this wrong
    ("Bash(python3 -c ' *)",                   "UNBOUNDED"),
    ("Bash(sh -)",                             "UNBOUNDED"),
    ("Bash(curl example.com | sh)",            "UNBOUNDED"),
    ("Bash(python3)",                          "UNBOUNDED"),
    ("Bash(* --version)",                      "UNBOUNDED"),
    ("Bash",                                   "BLANKET"),
    ("Bash(*)",                                "BLANKET"),
    ("Bash(python3 triage.py -)",              "NARROW"),      # v2 over-flagged this
    ("Bash(python3 triage.py sample.json)",    "NARROW"),
    ("Bash(npm run *)",                        "BROAD"),
    ("Bash(git commit *)",                     "BROAD"),
    ("Bash(open lessons/0001.html)",           "NARROW"),
    ("WebFetch(domain:example.com)",           "NON-BASH"),
    ("WebSearch",                              "WHOLE-TOOL"),  # unscoped, but not RCE
]

# L12 D2 corpus — floor membership, kept separate so the grade tests stay clean.
FLOOR_TEST = [
    ("echo \"exit=$?\"",              "YES"),
    ("grep -n pattern file.txt",       "YES"),
    ("ls -la",                         "YES"),
    ("cat README.md",                  "YES"),
    ("/bin/ls -la",                    "UNKNOWN"),  # path form: undocumented
    ("sed -n '1,12p'",                 "UNKNOWN"),  # never in the floor list
    ("ls > out.txt",                   "NO"),       # redirect = a file write
    ("find . -name '*.py' *",          "NO"),       # unquoted glob, write-capable
    ("cd packages/api && git log",     "NO"),       # cd + git executes hooks
    ("open lessons/0001.html",         "NO"),
    ("python3 triage.py x.json",       "NO"),
]


def self_test():
    print(" SELF-TEST · the two failures this tool made about itself are cases 1 and 9")
    print(" " + "-" * 72)
    bad = 0
    for rule, want in SELF_TEST:
        got, _ = classify(rule)
        ok = got == want
        bad += 0 if ok else 1
        print("  %-5s %-38s %-10s %s" % ("PASS" if ok else "FAIL", rule[:38], got,
                                         "" if ok else "(want %s)" % want))
    print("\n %d/%d pass" % (len(SELF_TEST) - bad, len(SELF_TEST)))

    print("\n FLOOR SELF-TEST · UNKNOWN is a real answer, not a failure")
    print(" " + "-" * 72)
    fbad = 0
    for spec, want in FLOOR_TEST:
        got, _ = floor_status(spec)
        ok = got == want
        fbad += 0 if ok else 1
        print("  %-5s %-34s %-9s %s" % ("PASS" if ok else "FAIL", spec[:34], got,
                                        "" if ok else "(want %s)" % want))
    print("\n %d/%d pass" % (len(FLOOR_TEST) - fbad, len(FLOOR_TEST)))
    return 1 if (bad or fbad) else 0


# --------------------------------------------------------------------------
# L12 D2 — THE FLOOR YOU DIDN'T HAVE TO WRITE
#
# Claude Code "recognizes a built-in set of Bash commands as read-only and runs
# them without a permission prompt IN EVERY MODE. The set is NOT CONFIGURABLE;
# to require a prompt for one of these commands, add an `ask` or `deny` rule."
#   https://code.claude.com/docs/en/permissions#read-only-commands  (2026-08-25)
#
# Consequence for a deliberate allowlist: a rule that only re-states the floor
# buys nothing. It is not dangerous, it is NOISE — and noise is what stopped
# anybody reading the list in the first place.
#
# The floor cannot be widened, only narrowed. So `ask`/`deny` are the ONLY
# levers over it, and in dontAsk mode an `ask` rule is a CONDITIONAL DENY.

READONLY_FLOOR = {"ls", "cat", "echo", "pwd", "head", "tail", "grep", "find",
                  "wc", "which", "diff", "stat", "du", "cd"}

# Documented exceptions that pull a command back OUT of the floor.
GLOB_UNSAFE = {"find", "sort", "sed", "git"}   # write/exec-capable flags


def floor_status(spec):
    """
    Is this rule already covered by the built-in read-only floor?
      "YES"     -> documented floor member, no documented exception applies
      "UNKNOWN" -> I cannot tell from the docs. Say so; do not guess.
      "NO"      -> not a floor command
    Returns (status, note).
    """
    if not spec:
        return "NO", ""
    s = spec.strip()

    # A redirect makes the TARGET a file write, checked against Edit rules and
    # protected paths. That is outside the floor regardless of the command.
    if re.search(r"(?<![0-9<>])>{1,2}(?!&)|\b2>", s):
        return "NO", "output redirect — the target is checked as a file write"

    head = s.split()[0] if s.split() else ""
    base = head.rsplit("/", 1)[-1]

    # Absolute/relative path to the binary. The docs enumerate BARE names.
    # Whether `/bin/ls` is canonicalised to `ls` before the floor check is NOT
    # stated anywhere I could find. Refusing to guess is the point.
    if "/" in head and base in READONLY_FLOOR:
        return "UNKNOWN", ("`%s` is the floor command `%s` given by path; the docs "
                           "enumerate bare names and do not say whether the path form "
                           "is canonicalised. TEST IT, do not assume." % (head, base))

    if base not in READONLY_FLOOR:
        # sed/awk/sort are named only in the GLOB exception sentence, never in
        # the floor list itself. Genuinely ambiguous.
        if base in ("sed", "sort", "awk"):
            return "UNKNOWN", ("`%s` appears in the docs only as a write-capable-flag "
                               "exception, never in the enumerated floor set. "
                               "Membership is undetermined." % base)
        return "NO", ""

    # Unquoted glob + a command that has write/exec-capable flags -> prompts.
    if base in GLOB_UNSAFE and re.search(r"(?<![\"'])\*", s):
        return "NO", "unquoted glob on a write-capable command — falls out of the floor"

    if base == "cd" and re.search(r"\bgit\b", s):
        return "NO", "cd + git — a new directory can execute that directory's hooks"

    return "YES", "built-in read-only floor covers this in every mode, with no rule"


def propose(rows):
    """Print the allowlist you would have written on purpose."""
    buckets = {"REDUNDANT": [], "UNKNOWN": [], "DROP": [], "KEEP": []}
    for grade, scope, rule, why, stale in rows:
        tool, spec = parse(rule)
        if grade in ("BLANKET", "UNBOUNDED"):
            buckets["DROP"].append((rule, "permits arbitrary code — %s" % why))
            continue
        if stale:
            buckets["DROP"].append((rule, "cruft: names %s, which is gone" % stale))
            continue
        if tool == "Bash":
            st, note = floor_status(spec)
            if st == "YES":
                buckets["REDUNDANT"].append((rule, note))
                continue
            if st == "UNKNOWN":
                buckets["UNKNOWN"].append((rule, note))
                continue
        buckets["KEEP"].append((rule, why or "deliberate grant"))

    print("\n" + "=" * 76)
    print(" PROPOSED DELIBERATE ALLOWLIST")
    print("=" * 76)
    for name, blurb in (
        ("DROP", "delete: unbounded, or names something that no longer exists"),
        ("REDUNDANT", "delete: the built-in read-only floor already runs these, in EVERY mode"),
        ("UNKNOWN", "TEST FIRST: I cannot determine floor membership from the docs"),
        ("KEEP", "the rules you would actually have sat down and written"),
    ):
        hits = buckets[name]
        print("\n %s (%d) — %s" % (name, len(hits), blurb))
        print(" " + "-" * 74)
        for rule, note in hits:
            print("  %s" % str(rule)[:70])
            if note:
                print("      -> %s" % note[:66])

    keep, drop = len(buckets["KEEP"]), len(buckets["DROP"]) + len(buckets["REDUNDANT"])
    total = sum(len(v) for v in buckets.values())
    print("\n" + "=" * 76)
    print(" %d rules in. %d deliberate, %d deletable, %d need a test first."
          % (total, keep, drop, len(buckets["UNKNOWN"])))
    print("""
 dontAsk READINESS
   In dontAsk mode Claude runs ONLY: your allow rules, the built-in read-only
   floor, and calls your PreToolUse hook approves. Everything else is denied
   outright — no prompt, no classifier.

   So the question is not "is my allowlist complete?" It is:
     * does the FLOOR cover my read side?          (it covers %d of these rules)
     * does my HOOK cover the judgement calls?     (that is the approver)
     * do my DENY rules cover the circuit breakers? (nothing overrides them)

   Note the asymmetry you are relying on:
     - a hook exit-2 BEATS an allow rule  (blocks before rules are evaluated)
     - a hook "allow" does NOT beat deny or ask rules
   The hook is a one-way ratchet. It can only tighten. That is why it is safe
   to point it at an external decision point.

   And an `ask` rule in dontAsk mode is a CONDITIONAL DENY: it prompts in
   Manual, denies here. It is the only lever that narrows the floor.""" % len(buckets["REDUNDANT"]))
    print("=" * 76)
    return 0


@_cli.entrypoint
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", default=".")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--propose", action="store_true",
                    help="emit the allowlist you would have written on purpose")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    _cli.chdir_project(args.project)
    root = Path.cwd()

    rows = []
    for name, path in SCOPES:
        cfg = load(path)
        for rule in ((cfg or {}).get("permissions", {}) or {}).get("allow", []) or []:
            grade, why = classify(rule)
            rows.append((grade, name, rule, why, dead(parse(rule)[1], root)))

    if args.propose:
        return propose(rows)

    print("=" * 76)
    print(" ALLOWLIST AUDIT · the policy you derived from your own behaviour")
    print(" project: %s" % root)
    print("=" * 76)
    # Always state the denominator. "No rules found" is only meaningful if you
    # can see WHICH scopes were actually read -- otherwise a missing project
    # config and a clean project config look identical.
    present = [n for n, path in SCOPES if load(path) is not None]
    absent = [n for n, path in SCOPES if load(path) is None]
    print("\n  scopes read: %s" % (", ".join(present) or "NONE"))
    if absent:
        print("  scopes absent: %s" % ", ".join(absent))

    if not rows:
        # Found 2026-09-20 by running this from /tmp during the portability
        # work: it printed this line and exited 0. "No rules found" and "rules
        # found and they are fine" were the same green light, so a renamed
        # settings file, a wrong --project, or a CI runner without the config
        # would pass this check forever. NOTHING AUDITED IS NOT A PASS.
        any_config = any(load(path) is not None for _, path in SCOPES)
        if not any_config:
            raise _cli.NotAudited(
                "NOT AUDITED: no Claude Code settings file exists in any\n"
                "       scope under %s\n"
                "       This is a configuration failure, not a clean result. If you\n"
                "       meant to audit a project, check --project; if this runner\n"
                "       genuinely has no config, do not gate on this check." % root)
        print("\n  No allow rules in any scope. Nothing pre-approved.")
        print("  (A settings file exists and contains no allow rules -- that is")
        print("   a real, audited result, unlike the case above.)")
        return 0

    order = {"BLANKET": 0, "UNBOUNDED": 1, "BROAD": 2, "WHOLE-TOOL": 3,
             "NARROW": 4, "NON-BASH": 5}
    rows.sort(key=lambda r: (order.get(r[0], 9), r[1]))
    counts = {}
    for g, *_ in rows:
        counts[g] = counts.get(g, 0) + 1

    print("\n  %-10s %s" % ("grade", "count   what it means"))
    print("  " + "-" * 72)
    for g in ("BLANKET", "UNBOUNDED", "BROAD", "WHOLE-TOOL", "NARROW", "NON-BASH"):
        if g in counts:
            meaning = {"BLANKET": "a whole tool, pre-approved",
                       "UNBOUNDED": "ARBITRARY CODE — the program is not in the rule",
                       "BROAD": "bounded binary, unbounded arguments",
                       "WHOLE-TOOL": "a non-shell tool, entirely unscoped",
                       "NARROW": "one command, fully spelled out",
                       "NON-BASH": "graded elsewhere (domains, paths, MCP)"}[g]
            print("  %-10s %-7d %s" % (g, counts[g], meaning))

    for g in ("BLANKET", "UNBOUNDED", "BROAD", "WHOLE-TOOL"):
        hits = [r for r in rows if r[0] == g]
        if not hits:
            continue
        print("\n" + "-" * 76)
        print(" %s" % g)
        print("-" * 76)
        for _, scope, rule, why, _d in hits:
            print("  [%s] %s" % (scope, rule))
            print("        -> %s" % why)

    stale = [r for r in rows if r[4]]
    if stale:
        print("\n" + "-" * 76)
        print(" CRUFT · rules naming files that are no longer here (%d)" % len(stale))
        print("-" * 76)
        for _, scope, rule, _w, tok in stale:
            print("  [%s] missing %-28s %s" % (scope, tok, str(rule)[:40]))
        print("\n  Not dangerous, but a grant you are no longer using is a grant")
        print("  nobody will review. An allowlist only shrinks on purpose.")

    # Only shell-reachable grades count as arbitrary code execution. A bare
    # WebSearch is scope creep, not RCE — counting it would inflate the headline
    # and teach the wrong reflex.
    unbounded = counts.get("UNBOUNDED", 0) + counts.get("BLANKET", 0)
    print("\n" + "=" * 76)
    if unbounded:
        print(" %d rule(s) permit arbitrary code execution." % unbounded)
        print(" Every one of them was created by approving a command you wanted to")
        print(" run at the time. That is what a behaviour-derived policy is: it")
        print(" inherits every decision you made while thinking about something else.")
    else:
        print(" No unbounded rules. Now check the BROAD list by hand: 'bounded binary,")
        print(" unbounded arguments' is a judgement call this script cannot make.")
    print("=" * 76)
    print("""
 RUN-BOOK · two things to observe, not assume:
   1. Auto mode drops wildcarded interpreters and restores them when you leave.
      In auto mode, does `python3 -c 'print(1)'` still run unprompted?
      Expect: NO (rule dropped). Then Shift+Tab to Manual and retry.
   2. `Bash(python3 -)` has no wildcard, so "narrow rules carry over" should
      apply and it should survive auto mode. THIS IS INFERENCE — the docs do
      not name this case. If it carries over, the most dangerous rule in the
      list is the one that survives because it looks narrow.""")
    return 1 if unbounded else 0


if __name__ == "__main__":
    sys.exit(main())
