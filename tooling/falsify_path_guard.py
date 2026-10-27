#!/usr/bin/env python3
"""
falsify_path_guard.py — does a deny rule on a path actually protect the path?

Claude Code's permission rules live in a file the agent can write, and the
obvious fix is:

    "deny": ["Write(.claude/settings*.json)", "Edit(.claude/settings*.json)"]

This script exists to attack that fix rather than admire it. A deny rule names a
TOOL. An attacker does not want a tool, it wants an EFFECT — bytes changed in a
file. So the question is not "is Write denied?" but:

    which of the surfaces that can produce this effect are covered?

Every uncovered surface is an equivalent-effect path: same outcome, different
tool, no rule in the way -- like a sibling tool reaching the transport that a
guarded tool was protecting. See docs/design-notes.md#rules-name-tools-not-effects.

REVISED 2026-08-16. The first version of this script inferred matching semantics
because the settings reference doesn't document them. The PERMISSIONS reference
does, and it says two things that changed the model:

  * Only `Read(path)` and `Edit(path)` rules are ever consulted for file access.
    A path rule written for Write, NotebookEdit, Glob or MultiEdit is accepted
    and NEVER USED (startup warning). So `deny: Write(.claude/settings*.json)`
    is an INERT RULE THAT READS LIKE A CONTROL. Meanwhile `Edit(path)` covers
    every built-in editing tool, so one correct rule beats the two-rule fix above.
  * Read/Edit deny rules ALSO apply to file commands Claude Code recognises in
    Bash — "such as cat, head, tail, and sed" — but NOT to "arbitrary
    subprocesses that read or write files indirectly, like a Python or Node
    script that opens files itself."

So the honest verdict per shell surface is three-valued, not two: COVERED (a
recognised file command), UNCOVERED (an interpreter, excluded by name), and
UNKNOWN (the docs say "such as", so the recognised set is not enumerated).
UNKNOWN is not a pass — it is the reason the run-book exists.

2026-09-07: one UNKNOWN closed by reading, not by running. Output redirects
(`>`, `>>`, `2>`) are documented as checked against your Edit allow/deny rules,
protected paths and working directories. Reclassified to "recognised". The
remaining UNKNOWNs (tee, cp, mv, truncate, dd, git) are still untested.

WHAT THIS CAN AND CANNOT PROVE — read before believing the output:
  * It is STATIC. It reads your settings files and reasons about rule coverage.
    It never invokes a tool, so it cannot observe enforcement.
  * Its real output is a RUN-BOOK: an ordered list of attempts to make in a
    fresh session, where the enforcement actually lives. The verdict is what the
    terminal does, not what this prints.
  * A surface reported as covered may still be bypassable by a spelling this
    script did not enumerate. Absence of a finding is not evidence of coverage.

USAGE:
    python3 falsify_path_guard.py [--path .claude/settings.json] [--project DIR]
Exit 0 = every enumerated surface is covered by a deny rule, 1 = gaps found.
"""
import argparse
import fnmatch
import json
import os
import re
import sys
from pathlib import Path

HOME = Path.home()

SCOPES = [
    ("user",    HOME / ".claude" / "settings.json"),
    ("project", Path(".claude") / "settings.json"),
    ("local",   Path(".claude") / "settings.local.json"),
    ("managed", Path("/Library/Application Support/ClaudeCode/managed-settings.json")),
]

# Non-Bash tools that can change bytes in a file.
FILE_TOOLS = ["Write", "Edit", "NotebookEdit"]

# Rule tool-names that Claude Code CONSULTS for file access. Anything else with
# a path specifier is accepted, warned about at startup, and never used.
CONSULTED = ("Read", "Edit")
INERT_WITH_PATH = ("Write", "NotebookEdit", "Glob", "MultiEdit")

# Which consulted rule covers which file tool.
#   Edit(p) -> every built-in editing tool.  Read(p) -> reads + Edit + Write,
#   but NOT NotebookEdit (docs are explicit: "add an Edit deny rule for paths
#   no tool may change").
COVERED_BY = {"Edit": ("Write", "Edit", "NotebookEdit"), "Read": ("Write", "Edit")}

# Shell families that change bytes in a file. Each entry:
#   (label, probe, command template, class)
# class: "recognised" — a file command the docs name, so a Read/Edit deny reaches it
#        "interpreter" — explicitly excluded: an arbitrary subprocess opening files
#        "unknown"    — the docs say "such as", so this one is untested, not safe
BASH_FAMILIES = [
    # RECLASSIFIED 2026-09-07 (was "unknown"): "for `> file`, `>> file`, or `2> file`,
    # the check covers your `Edit` allow and deny rules, protected paths, and the
    # working directories." A target starting with ~ or containing a glob still
    # needs approval. So the redirect is reached by an Edit deny rule after all —
    # this is the run-book's central question, answered by the docs, not the canary.
    ("sh redirect", ">>",        'echo "//canary" >> %s',                                  "recognised"),
    ("sed",         "sed",       'sed -i "" -e "$ a\\\\" %s',                              "recognised"),
    ("cat heredoc", "cat",       'cat > %s <<< "{}"',                                      "recognised"),
    ("tee",         "tee",       'echo "{}" | tee -a %s',                                  "unknown"),
    ("python",      "python3",   'python3 -c "open(\'%s\',\'a\').write(\'//canary\')"',    "interpreter"),
    ("perl",        "perl",      'perl -pi -e "s/$/ /" %s',                                "interpreter"),
    ("node",        "node",      'node -e "require(\'fs\').appendFileSync(\'%s\',\'x\')"', "interpreter"),
    ("cp",          "cp",        'cp /tmp/replacement.json %s',                            "unknown"),
    ("mv",          "mv",        'mv /tmp/replacement.json %s',                            "unknown"),
    ("truncate",    "truncate",  'truncate -s 0 %s',                                       "unknown"),
    ("dd",          "dd",        'dd of=%s if=/dev/null',                                  "unknown"),
    ("git",         "git",       'git checkout -- %s',                                     "unknown"),
]


def load(path):
    try:
        return json.loads(path.read_text()), None
    except FileNotFoundError:
        return None, None
    except json.JSONDecodeError as e:
        return None, "malformed JSON: %s" % e
    except PermissionError:
        return None, "unreadable (permission denied)"


def parse_rule(rule):
    """'Write(.claude/settings*.json)' -> ('Write', '.claude/settings*.json')."""
    m = re.match(r"^\s*([A-Za-z_][\w]*)\s*\((.*)\)\s*$", str(rule))
    if m:
        return m.group(1), m.group(2).strip()
    return str(rule).strip(), None


def path_matches(pattern, target):
    """Loose glob match, tolerant of ./ prefixes and ** segments."""
    if pattern is None:
        return True                      # bare `Write` denies the whole tool
    p = pattern.lstrip("./")
    t = str(target).lstrip("./")
    return (fnmatch.fnmatch(t, p) or fnmatch.fnmatch(t, p.replace("**", "*"))
            or fnmatch.fnmatch(t, "*" + p) or p == t)



# ---------------------------------------------------------------------------
# SURFACE C · containment
#
# The three interpreter rows above are UNCOVERED because permission rules are
# an ENUMERATION: they name tools and commands, and "a Python or Node script
# that opens files itself" is excluded by name. The sandbox is not an
# enumeration -- it is an OS boundary "enforced ... for every Bash command and
# its child processes" (Seatbelt on macOS, namespaces on Linux/WSL2).
#
# But it does NOT close the row everywhere, and the difference is the point:
#
#   * Sandboxed commands CAN write the working directory by default. A canary
#     in your own repo is inside the boundary, so `python3 -c "open(...)"`
#     still reaches it. Inside the boundary, enumeration is all you have.
#   * The sandbox keeps its own PROTECTED PATHS -- config and code Claude Code
#     loads -- denied even inside writable directories, because "a command that
#     could edit those files could grant itself permissions, or add a hook or
#     MCP server that Claude Code runs outside the sandbox." There is no way to
#     exempt one: "an allowWrite entry or an Edit allow rule that covers the
#     path doesn't lift the protection."
#
# So CONTAINED is reported only for a target on that protected list, and only
# when all three switches are set. Source: /docs/en/sandboxing, verified
# 2026-09-14.
# ---------------------------------------------------------------------------

# Protected within allowed. Working directory and the directories above it,
# plus the user config dir. Not exhaustive -- `/sandbox` Config tab resolves
# the full list for your machine under "Denied within allowed".
SANDBOX_PROTECTED = [
    ".claude/settings.json", ".claude/settings.local.json", ".claude/settings*.json",
    ".claude/skills/**", ".claude/agents/**", ".claude/commands/**",
    ".claude/hooks/**", ".claude/workflows/**", ".claude/scheduled_tasks.json",
    ".mcp.json", ".bashrc", ".zshrc", ".gitconfig", ".vscode/**", ".idea/**",
    ".git/hooks/**", ".git/config",
    "~/.claude/**", "~/.claude.json",
]


def sandbox_switches():
    """Merged sandbox posture. Returns (enabled, fs_on, hatch_closed, notes)."""
    enabled = fs_on = hatch_closed = False
    notes = []
    for name, path in SCOPES:
        cfg, _ = load(path)
        sb = ((cfg or {}).get("sandbox") or {})
        if not sb:
            continue
        if sb.get("enabled") is True:
            enabled = True
            notes.append("sandbox.enabled in %s" % name)
        if (sb.get("filesystem") or {}).get("disabled") is True:
            fs_on = False
            notes.append("filesystem.disabled in %s -- isolation OFF" % name)
        elif enabled:
            fs_on = True
        if sb.get("allowUnsandboxedCommands") is False:
            hatch_closed = True
            notes.append("allowUnsandboxedCommands:false in %s" % name)
    return enabled, fs_on, hatch_closed, notes


def sandbox_verdict(target):
    """('CONTAINED'|'NOT CONTAINED', reason) for an interpreter writing target."""
    enabled, fs_on, hatch_closed, _ = sandbox_switches()
    protected = any(path_matches(pat, target) for pat in SANDBOX_PROTECTED)
    if not enabled:
        return "NOT CONTAINED", "sandbox not enabled in any scope"
    if not fs_on:
        return "NOT CONTAINED", "filesystem isolation disabled"
    if not protected:
        return "NOT CONTAINED", "target is writable inside the sandbox (cwd)"
    if not hatch_closed:
        return "NOT CONTAINED", "escape hatch open: the model may retry unsandboxed"
    return "CONTAINED", "sandbox protected path, isolation on, hatch closed"

def bash_covered(pattern, probe):
    """Does a Bash(...) deny pattern plausibly match a command using `probe`?"""
    if pattern is None:
        return True                      # bare `Bash` denies all shell
    p = pattern.strip()
    if p in ("*", "**"):
        return True
    return p.split()[0].lstrip("./").startswith(probe) or probe in p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", default=".claude/settings.json",
                    help="the file whose protection you are falsifying")
    ap.add_argument("--project", default=".")
    args = ap.parse_args()
    os.chdir(args.project)
    target = args.path

    print("=" * 74)
    print(" FALSIFY A PATH GUARD · does a deny rule on a TOOL protect an EFFECT?")
    print(" target file : %s" % target)
    print(" project     : %s" % Path.cwd())
    print("=" * 74)

    deny = []
    print("\n  scope     file                                   deny rules")
    print("  " + "-" * 70)
    for name, path in SCOPES:
        cfg, err = load(path)
        rules = ((cfg or {}).get("permissions", {}) or {}).get("deny", []) or []
        deny += rules
        print("  %-9s %-38s %s" % (name, str(path)[-38:], err or len(rules)))
    print("\n  %d deny rule(s) merged across scopes (deny beats allow)." % len(deny))

    parsed = [parse_rule(r) for r in deny]

    # ---- surface 0: rules that look like controls and are not -------------
    inert = ["%s(%s)" % (t, p) for (t, p) in parsed
             if t in INERT_WITH_PATH and p is not None]
    if inert:
        print("\n" + "-" * 74)
        print(" INERT RULES · accepted, warned about at startup, never consulted")
        print("-" * 74)
        for r in inert:
            print("  %-46s writes an Edit(...) rule instead" % r)

    # ---- surface 1: the file tools ----------------------------------------
    print("\n" + "-" * 74)
    print(" SURFACE A · tools whose whole job is writing files")
    print("-" * 74)
    gaps = []
    for tool in FILE_TOOLS:
        via = next(("%s(%s)" % (t, p) for (t, p) in parsed
                    if t in CONSULTED and path_matches(p, target)
                    and tool in COVERED_BY[t]), None)
        if not via:
            gaps.append(tool)
        print("  %-14s %s" % (tool, ("COVERED  by %s" % via) if via else "UNCOVERED"))

    # ---- surface 2: the shell --------------------------------------------
    print("\n" + "-" * 74)
    print(" SURFACE B · the shell, i.e. every other way to change those bytes")
    print("-" * 74)
    bash_rules = [(t, p) for (t, p) in parsed if t == "Bash"]
    file_rule = next(("%s(%s)" % (t, p) for (t, p) in parsed
                      if t in CONSULTED and path_matches(p, target)), None)
    shell_gaps, unknowns = [], []
    for label, probe, template, klass in BASH_FAMILIES:
        hits = [p for (t, p) in bash_rules if bash_covered(p, probe)]
        if hits:
            print("  %-14s COVERED    by Bash(%s)" % (label, hits[0]))
        elif file_rule and klass == "recognised":
            print("  %-14s COVERED    a file cmd the docs name, via %s" % (label, file_rule))
        elif klass == "interpreter":
            verdict, why = sandbox_verdict(target)
            if verdict == "CONTAINED":
                print("  %-14s CONTAINED  %s" % (label, why))
            else:
                shell_gaps.append((label, template))
                print("  %-14s UNCOVERED  arbitrary subprocess — excluded by name" % label)
                print("  %-14s           containment: %s" % ("", why))
        elif file_rule:
            unknowns.append((label, template))
            print("  %-14s UNKNOWN    outside the docs' \"such as\" list — go test it" % label)
        else:
            shell_gaps.append((label, template))
            print("  %-14s UNCOVERED  no file rule on this path at all" % label)

    # ---- the verdict ------------------------------------------------------
    print("\n" + "=" * 74)
    if not gaps and not shell_gaps and not unknowns:
        print(" No enumerated surface is uncovered. Now go disprove that:")
        print(" absence of a finding here is not evidence of coverage — this")
        print(" script only knows the spellings it was taught.")
    else:
        print(" %d file-tool gap(s), %d shell gap(s), %d unknown."
              % (len(gaps), len(shell_gaps), len(unknowns)))
        if inert:
            print(" %d rule(s) above are INERT: a path rule on Write/NotebookEdit/" % len(inert))
            print(" Glob/MultiEdit is never consulted. It reads like a control.")
        print(" Interpreters are excluded BY THE VENDOR, not by oversight:")
        print(" a Python or Node script opening a file is out of scope for")
        print(" permission rules. That gap closes a rung down (sandbox), or")
        print(" at a PreToolUse hook — never with rule number fifteen.")
    print("=" * 74)

    # ---- the run-book: where the real verdict comes from ------------------
    print("\n RUN-BOOK · try these in a FRESH session (rules load at start),")
    print(" in this order, and write down what actually happened:\n")
    n = 0
    for tool in FILE_TOOLS:
        n += 1
        print("  %d. [%s] ask the agent to append a comment to %s" % (n, tool, target))
        print("     predict: %s" % ("BLOCKED" if tool not in gaps else "ALLOWED — no consulted rule covers it"))
    for label, template in (shell_gaps + unknowns)[:5]:
        n += 1
        print("  %d. [Bash · %s] %s" % (n, label, template % target))
        print("     predict: %s" % ("ALLOWED — vendor excludes arbitrary subprocesses"
                                    if (label, template) in shell_gaps else
                                    "UNKNOWN — this is the observation worth making"))
    print("""
 Do it against a CANARY — and put the canary OUTSIDE .claude/:
   1. mkdir -p canary && echo '{}' > canary/policy-canary.json
   2. add   "deny": ["Edit(canary/policy-canary.json)",
                     "Read(canary/policy-canary.json)"]
            (Edit(...) covers Edit + Write + NotebookEdit. A Write(...) path
             rule is never consulted — do not write one and feel protected.)
   3. restart the session; work the run-book with --path canary/policy-canary.json

 WHY NOT .claude/ — learned the hard way 2026-08-17. `.claude` is a BUILT-IN
 PROTECTED DIRECTORY: writes there are never auto-approved, allow rules do not
 pre-approve them, and the per-mode outcome (prompt / classifier / denied /
 allowed) is decided before your rules are consulted. A canary in .claude/
 measures that mechanism, not your rule. A control experiment cannot run inside
 a directory the product already controls.

 RECORD THE MECHANISM, NOT JUST THE OUTCOME. "Deterministic deny", "permission
 prompt", and "Blocked by classifier" are three different findings that all
 look like "it didn't happen". Note which permission MODE you were in.

 STATIC-ONLY REMINDER: coverage above is read from documented semantics
 (permissions reference, verified 2026-08-16), not from observed enforcement.
 The recognised-Bash-command list is given as "such as" — hence UNKNOWN.
 Your terminal is the authority; this is the checklist.""")

    return 1 if (gaps or shell_gaps or unknowns) else 0


if __name__ == "__main__":
    sys.exit(main())
