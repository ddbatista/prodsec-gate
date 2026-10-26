#!/usr/bin/env python3
"""
policy_guard_hook.py — L10 Day 2: one choke point instead of fourteen wrappers.

Day 1 counted the surfaces that can change bytes in .claude/settings.json and
found L08's prescription (`deny: Write/Edit(...)`) covers 2 of 14. The answer is
not rule number fifteen. It is to stop naming tools and start standing where the
calls converge: a PreToolUse hook, which sees EVERY tool call before it runs.

  stdin  <- {"hook_event_name":"PreToolUse","tool_name":"Bash",
             "tool_input":{"command":"echo x >> .claude/settings.json"}, ...}
  stdout -> {"hookSpecificOutput":{"hookEventName":"PreToolUse",
             "permissionDecision":"deny","permissionDecisionReason":"..."}}

Verified against the Claude Code hooks reference and guide, 2026-08-16:
  * PreToolUse input carries `tool_name` and `tool_input` (Bash -> `command`,
    file tools -> `file_path`), plus `permission_mode`.
  * exit 0 + JSON decision `allow|deny|ask`, or exit 2 + stderr, blocks a call.
  * ANY OTHER EXIT CODE IS A NON-BLOCKING ERROR AND THE TOOL CALL PROCEEDS.
    A crashing guard is an open guard, so every path here is wrapped and the
    except branch DENIES. See fail_closed().
  * The matcher is itself an allowlist of tool names. `"*"` matches all tools;
    `Bash|Write|Edit|NotebookEdit` does not cover an MCP write tool. See
    --self-test, section GAPS.

WHAT THIS DOES NOT DO — read before trusting it:
  * For Bash it matches on the SPELLING of the command string. That is the
    allowlist-as-parser shape from L09, seen from the deny side: the shell can
    build a path the guard never sees. That is why anything that both conceals
    a target and writes something returns "ask" (a human) rather than "allow".
  * Consequently it over-blocks: `cat .claude/settings.json` is a read and is
    denied anyway, because this guard cannot tell read from write in arbitrary
    shell. That false-positive tax is the price of an effect-based deny, and
    --self-test counts it out loud rather than hiding it.
  * It protects a file. It does not protect ITSELF from the same enumeration:
    a hook is a file on disk in the same write path. See the CODA at the bottom.

USAGE
  as a hook   (registered in settings.json; reads stdin, writes a decision)
  --self-test run the decision table offline: PASS/FAIL per case, exit 1 on FAIL
  --protect P add a protected path (repeatable; defaults below)
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

DEFAULT_PROTECTED = [
    ".claude/settings.json",
    ".claude/settings.local.json",
    "canary/policy-canary.json",           # neutral canary (NOT in .claude/ — protected dir)
    "tooling/policy_guard_hook.py",        # the guard protecting the guard
]

# Fields under tool_input that name a file, across the tools that write one.
PATH_FIELDS = ("file_path", "notebook_path", "path", "filePath", "target_file")

# Shell constructs that WRITE. Deliberately the Day 1 vocabulary, plus editors.
WRITE_HINTS = [
    r">>", r"(?<![0-9<>])>(?!&)", r"\btee\b", r"\bsed\b\s+-i", r"\bcp\b", r"\bmv\b",
    r"\btruncate\b", r"\bdd\b\s+.*\bof=", r"\bperl\b\s+-\w*i", r"\bpython3?\b\s+-c",
    r"\bopen\s*\([^)]*['\"][aw]", r"\bvim?\b", r"\bnano\b", r"\bed\b\s", r"\bgit\b\s+checkout",
    r"\binstall\b\s+-m", r"\bpatch\b", r"\bln\b",
    # piping into an interpreter is unbounded execution, so treat it as a
    # possible write: we cannot bound what the decoded/produced program does.
    r"\|\s*(sh|bash|zsh|python3?|perl|ruby|node)\b",
]

# Constructs that hide the effective target from a string match. Presence of any
# of these plus a write hint means the guard is reading a command whose real
# target it cannot see — the honest answer to that is a human, not "allow".
CONCEAL_HINTS = [
    r"\$\(", r"`", r"\$\{?[A-Za-z_]", r"\bbase64\b", r"\bxxd\b", r"\beval\b",
    r"\bprintf\b.*\|", r"\bsource\b", r"\.\s+/",
]


def tokens_for(protected):
    """Every spelling of a protected path a shell command might contain."""
    out = set()
    for p in protected:
        p = str(p)
        expanded = os.path.expanduser(p)
        out.update({p, expanded, "./" + p.lstrip("./"), os.path.basename(p)})
        try:
            out.add(str(Path(expanded).resolve()))
        except OSError:
            pass
    return {t for t in out if t}


def named_path(tool_input):
    for f in PATH_FIELDS:
        v = tool_input.get(f)
        if isinstance(v, str) and v:
            return v
    return None


def same_file(candidate, protected):
    """Does an explicitly-named path point at a protected file?"""
    try:
        cand = Path(os.path.expanduser(candidate)).resolve()
    except (OSError, RuntimeError):
        return None
    for p in protected:
        try:
            if cand == Path(os.path.expanduser(p)).resolve():
                return p
        except (OSError, RuntimeError):
            continue
        if os.path.normpath(candidate).endswith(os.path.normpath(p)):
            return p
    return None


def any_match(patterns, text):
    return next((p for p in patterns if re.search(p, text, re.I)), None)


def decide(tool_name, tool_input, protected):
    """(decision, reason). decision in {deny, ask, None}. None = no opinion."""
    toks = tokens_for(protected)

    # --- surface A: a tool that names its target ---------------------------
    named = named_path(tool_input or {})
    if named:
        hit = same_file(named, protected)
        if hit:
            return "deny", ("%s targets the protected policy file %s. Policy "
                            "files are not agent-writable." % (tool_name, hit))

    # --- surface B: the shell ----------------------------------------------
    cmd = (tool_input or {}).get("command")
    if isinstance(cmd, str) and cmd:
        hit = next((t for t in toks if t and t.lower() in cmd.lower()), None)
        if hit:
            return "deny", ("shell command references the protected policy file "
                            "(%s). Denied on the effect, not the verb: this guard "
                            "does not try to decide which commands write." % hit)
        w, c = any_match(WRITE_HINTS, cmd), any_match(CONCEAL_HINTS, cmd)
        if w and c:
            return "ask", ("command both writes and builds its target indirectly, "
                           "so the guard cannot see what it writes to. Escalating "
                           "to you rather than guessing.")

    return None, None


def fail_closed(msg):
    emit("deny", "policy guard failed internally (%s). Denying: a guard that "
                 "errors is a guard that is not there." % msg)
    sys.exit(0)


def emit(decision, reason):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": reason,
    }}))


# --------------------------------------------------------------------------
# self-test: the feedback loop, offline. No session restart needed to iterate.
# --------------------------------------------------------------------------
P = ".claude/settings.json"
MUST_DENY = [
    ("Write",        {"file_path": P},                                    "Write"),
    ("Edit",         {"file_path": "./" + P},                             "Edit, ./ prefix"),
    ("NotebookEdit", {"notebook_path": P},                                "NotebookEdit"),
    ("Bash", {"command": 'echo "//canary" >> %s' % P},                    "sh redirect"),
    ("Bash", {"command": 'sed -i "" -e "$ a\\\\" %s' % P},                "sed"),
    ("Bash", {"command": 'echo "{}" | tee -a %s' % P},                    "tee"),
    ("Bash", {"command": "python3 -c \"open('%s','a').write('x')\"" % P}, "python"),
    ("Bash", {"command": 'perl -pi -e "s/$/ /" %s' % P},                  "perl"),
    ("Bash", {"command": "cp /tmp/replacement.json %s" % P},              "cp"),
    ("Bash", {"command": "mv /tmp/replacement.json %s" % P},              "mv"),
    ("Bash", {"command": 'cat > %s <<< "{}"' % P},                        "cat heredoc"),
    ("Bash", {"command": "truncate -s 0 %s" % P},                         "truncate"),
    ("Bash", {"command": "dd of=%s if=/dev/null" % P},                    "dd"),
    ("Bash", {"command": "git checkout -- %s" % P},                       "git"),
    ("Bash", {"command": "cd .claude && echo x >> settings.json"},        "cd + basename"),
    ("Bash", {"command": "vim ~/%s" % P},                                 "editor, ~ path"),
]
MUST_ASK = [
    ("Bash", {"command": "T=$(printf 'set%stings.json' ''); echo x >> .claude/$T"}, "split string"),
    ("Bash", {"command": "echo ZWNobyB4ID4+IC5jbGF1ZGU= | base64 -d | sh"},      "base64 pipe"),
]
MUST_PASS = [
    ("Bash",  {"command": "git status"},                    "unrelated shell"),
    ("Bash",  {"command": "npm test"},                      "unrelated shell"),
    ("Write", {"file_path": "README.md"},                   "unrelated write"),
    ("Bash",  {"command": "python3 tooling/triage.py -"},   "our own tooling"),
]
FALSE_POSITIVES = [
    ("Bash", {"command": "cat %s" % P},                              "a READ, denied anyway"),
    ("Bash", {"command": "python3 tooling/falsify_path_guard.py --path %s" % P,
              }, "our own auditor, denied anyway"),
]
KNOWN_GAPS = [
    ("mcp__filesystem__write_file", {"path": P},
     "decide() denies it — but matcher `Bash|Write|Edit|NotebookEdit` never "
     "delivers it. The matcher is an allowlist. Use \"*\"."),
    ("Bash", {"command": "bash /tmp/w.sh"},
     "no path, no conceal marker, no write hint visible: the write lives in a "
     "file written earlier. Two-step beats one-shot string matching."),
]


def self_test(protected):
    rows, fails = [], 0
    for label, cases, want in (("MUST DENY", MUST_DENY, "deny"),
                               ("MUST ASK", MUST_ASK, "ask"),
                               ("MUST NOT FIRE", MUST_PASS, None)):
        rows.append(("H", label, "", ""))
        for tool, ti, note in cases:
            got, _ = decide(tool, ti, protected)
            ok = got == want
            fails += 0 if ok else 1
            rows.append(("R", "PASS" if ok else "FAIL", note,
                         "%s -> %s (want %s)" % (tool, got, want)))
    rows.append(("H", "KNOWN FALSE POSITIVES (cost of denying on effect)", "", ""))
    for tool, ti, note in FALSE_POSITIVES:
        got, _ = decide(tool, ti, protected)
        rows.append(("R", "COST", note, "%s -> %s" % (tool, got)))
    rows.append(("H", "KNOWN GAPS (disclosed, not fixed)", "", ""))
    for tool, ti, note in KNOWN_GAPS:
        got, _ = decide(tool, ti, protected)
        rows.append(("R", "GAP", note, "%s -> %s" % (tool, got)))

    print("=" * 76)
    print(" POLICY GUARD · offline decision table · protecting:")
    for p in protected:
        print("   %s" % p)
    print("=" * 76)
    for kind, a, b, c in rows:
        if kind == "H":
            print("\n " + a)
            print(" " + "-" * 74)
        else:
            print("  %-5s %-34s %s" % (a, b[:34], c))
    total = len(MUST_DENY) + len(MUST_ASK) + len(MUST_PASS)
    print("\n" + "=" * 76)
    print(" %d/%d asserted cases pass. %d known gaps disclosed above." %
          (total - fails, total, len(KNOWN_GAPS)))
    print(" Offline PASS is not enforcement. The verdict is the Day 1 run-book,")
    print(" re-run in a fresh session with this hook registered. If the recorded")
    print(" outcomes do not CHANGE, the hook is not in the path.")
    print("=" * 76)
    return 1 if fails else 0


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--protect", action="append", default=None)
    args = ap.parse_args()
    protected = args.protect or DEFAULT_PROTECTED

    if args.self_test:
        return self_test(protected)

    try:
        raw = sys.stdin.read()
    except Exception as e:                                   # noqa: BLE001
        fail_closed("unreadable stdin: %s" % e)
    try:
        event = json.loads(raw or "{}")
    except json.JSONDecodeError as e:
        fail_closed("unparseable hook input: %s" % e)

    try:
        decision, reason = decide(event.get("tool_name", ""),
                                  event.get("tool_input") or {}, protected)
    except Exception as e:                                   # noqa: BLE001
        fail_closed(type(e).__name__)

    if decision:
        emit(decision, reason)
    return 0                          # silent exit 0 = no opinion; normal flow


if __name__ == "__main__":
    sys.exit(main())
