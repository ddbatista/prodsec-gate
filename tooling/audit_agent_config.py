#!/usr/bin/env python3
"""
audit_agent_config.py — audit YOUR coding agent against the placement ladder.

L08 (2026-08-03) built the Claude Code pass. L09 (2026-08-07) generalised it:
the audit is not a settings-file checklist, it is six portable questions asked
of whatever agent you happen to be running. Same ladder
(reference/control-placement-ladder.html), four targets:

    --agent claude    .claude/settings.json across four scopes
    --agent codex     ~/.codex/config.toml, .codex/config.toml, requirements.toml
    --agent cursor    ~/.cursor/permissions.json, <ws>/.cursor/permissions.json
    --agent harness   an agent YOU wrote — no config file, so audit the source
    --agent all       every target present on this machine

READ-ONLY. It never writes, and it never prints the contents of your config
files — only findings about them. Safe to run and safe to share the output.

Primary sources (verified on the date beside each):
  Claude Code  https://code.claude.com/docs/en/settings          2026-08-03
               https://code.claude.com/docs/en/hooks             2026-08-03
  Codex        https://developers.openai.com/codex/local-config  2026-08-07
               https://developers.openai.com/codex/sandboxing    2026-08-07
               .../codex/agent-approvals-security                2026-08-07
               .../codex/enterprise/managed-configuration        2026-08-07
  Cursor       https://cursor.com/docs/agent/security            2026-08-07
               https://cursor.com/docs/reference/permissions     2026-08-07
               GHSA-82wg-qcm4-fp2w / CVE-2026-22708 (allowlist bypass)

USAGE:  python3 audit_agent_config.py [--project DIR] [--agent TARGET]
Exit 0 = no high-severity findings, 1 = at least one HIGH,
2 = not audited (unreadable --project or a config file that exists but
    cannot be parsed -- including a Codex config.toml on Python < 3.11, which
    has no TOML parser).
"""
import argparse
import ast
import json
import os
import re
import sys
from pathlib import Path

try:
    import tomllib                     # stdlib on 3.11+; Codex config is TOML
except ModuleNotFoundError:            # pragma: no cover
    tomllib = None

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _cli                      # noqa: E402

HOME = Path.home()

# ---------------------------------------------------------------- Claude Code
# The four scopes, lowest precedence first (per the settings reference).
SCOPES = [
    ("user",    HOME / ".claude" / "settings.json",              "you, everywhere"),
    ("project", Path(".claude") / "settings.json",               "everyone on the repo"),
    ("local",   Path(".claude") / "settings.local.json",         "you, this repo (gitignored)"),
    ("managed", Path("/Library/Application Support/ClaudeCode/managed-settings.json"),
                "org policy — users cannot override"),
]

# Paths whose disclosure is the classic leg-② win for an injected agent.
SECRET_TARGETS = [".env", ".ssh", "credentials", "id_rsa", ".aws", "secrets"]

# Commands that are pure leg-③ egress.
EGRESS_COMMANDS = ["curl", "wget", "nc ", "ssh ", "scp "]

# --------------------------------------------------------------------- Codex
# Precedence per the config reference: CLI > project > profile > user > system.
CODEX_SCOPES = [
    ("project", Path(".codex") / "config.toml"),
    ("user",    HOME / ".codex" / "config.toml"),
    ("system",  Path("/etc/codex/config.toml")),
]
CODEX_REQUIREMENTS = Path("/etc/codex/requirements.toml")

# -------------------------------------------------------------------- Cursor
CURSOR_SCOPES = [
    ("user",      HOME / ".cursor" / "permissions.json"),
    ("workspace", Path(".cursor") / "permissions.json"),
]

# ------------------------------------------------------------------- harness
# Names that, appearing in a function, suggest it consults a gate before
# reaching the transport. A NAME check, not a semantic one — see LIMITS below.
GATE_HINTS = ["allowed", "allow_list", "allowlist", "enforce", "policy",
              "refuse", "denied", "permit", "authoriz"]
TRANSPORT_HINTS = ["post", "put", "request", "urlopen", "send", "connect"]


def load_json(path):
    """Return (parsed_dict, error_string). Never raises."""
    try:
        return json.loads(path.read_text()), None
    except FileNotFoundError:
        return None, None
    except json.JSONDecodeError as e:
        return None, "malformed JSON: %s" % e
    except PermissionError:
        return None, "unreadable (permission denied)"
    except OSError as e:
        return None, "unreadable (%s)" % e


def load_toml(path):
    """Return (parsed_dict, error_string). Never raises."""
    if tomllib is None:
        # Only a problem if there is a file we cannot read; an absent config
        # is audited the same on every Python.
        return None, ("needs Python 3.11+ (tomllib)" if Path(path).exists() else None)
    try:
        with open(path, "rb") as fh:
            return tomllib.load(fh), None
    except FileNotFoundError:
        return None, None
    except tomllib.TOMLDecodeError as e:
        return None, "malformed TOML: %s" % e
    except PermissionError:
        return None, "unreadable (permission denied)"
    except OSError as e:
        return None, "unreadable (%s)" % e


def rules(cfg, kind):
    return (cfg or {}).get("permissions", {}).get(kind, []) or []


def mentions(rule_list, needles):
    """Any rule containing any needle (case-insensitive substring).

    DEPRECATED for path and command matching -- see file_rules/command_rules.
    Kept only for callers that genuinely mean "this text appears somewhere".
    """
    return [r for r in rule_list for n in needles if n.lower() in str(r).lower()]


# --------------------------------------------------------------------------
# F8 (found 2026-09-17 by the L15 MAESTRO pass). mentions() is a bare
# substring test over whole rule text, and it was deciding two HIGH/OK
# findings. Two ways it was wrong, both verified:
#
#   * Write(.claude/settings*.json) matched, so the audit reported "the agent
#     cannot rewrite its own constraints" for a rule that is NEVER CONSULTED.
#     falsify_path_guard.py prints INERT for the same rule and exits 1. Two
#     tools, same directory, opposite verdicts -- and the reassuring one owned
#     the exit code. Record 0013 established this four weeks ago and the fix
#     landed in the prose and not in this function.
#   * WebFetch(domain:credentials.example.com) matched SECRET_TARGETS, so an
#     egress allow rule counted as evidence that secret paths were denied.
#
# Same defect as bash_covered()'s `probe in p` and the "falsif" grep: a
# substring test standing in for a structured check.
#
# Verified semantics (permissions reference): file access is checked against
# Edit(path) and Read(path) ONLY. A path rule on Write, NotebookEdit, Glob or
# MultiEdit is accepted, warned about at startup, and never consulted. A bare
# tool-name rule with no path DOES match, at tool level.
# --------------------------------------------------------------------------

FILE_CONSULTED = ("Edit", "Read")
FILE_INERT = ("Write", "NotebookEdit", "Glob", "MultiEdit")


def split_rule(rule):
    """'Edit(a/b*.json)' -> ('Edit', 'a/b*.json');  'Write' -> ('Write', None)."""
    m = re.match(r"^\s*([A-Za-z_][\w]*)\s*\((.*)\)\s*$", str(rule))
    return (m.group(1), m.group(2).strip()) if m else (str(rule).strip(), None)


def file_rules(rule_list, needles):
    """Path rules matching a needle, split into (consulted, inert).

    Only the PATH is matched, never the whole rule text -- that is what let a
    WebFetch domain rule pose as a secret-path deny.
    """
    consulted, inert = [], []
    for r in rule_list:
        tool, path = split_rule(r)
        if path is None:
            if tool in FILE_CONSULTED or tool in FILE_INERT:
                consulted.append(str(r))       # bare tool deny: real, tool-level
            continue
        if not any(n.lower() in path.lower() for n in needles):
            continue
        if tool in FILE_CONSULTED:
            consulted.append(str(r))
        elif tool in FILE_INERT:
            inert.append(str(r))
        # anything else (Bash, WebFetch, MCP...) is not a file rule at all
    return consulted, inert


def command_rules(rule_list, needles):
    """Bash rules whose COMMAND TEXT contains a needle. Bash rules only."""
    out = []
    for r in rule_list:
        tool, spec = split_rule(r)
        if tool != "Bash" or spec is None:
            continue
        if any(n.lower() in spec.lower() for n in needles):
            out.append(str(r))
    return out


def inventory(r, scopes, loader):
    """Print a scope table and return {name: cfg}; unreadable scopes go on r."""
    print("\n  scope     file                                   status")
    print("  " + "-" * 70)
    configs = {}
    for entry in scopes:
        name, path = entry[0], entry[1]
        cfg, err = loader(path)
        configs[name] = cfg
        if err:
            r.unread[str(path)] = err
        status = err or ("found" if cfg is not None else "absent")
        print("  %-9s %-38s %s" % (name, str(path)[-38:], status))
    return configs


class Report:
    def __init__(self):
        self.findings = []
        # Scopes that exist but could not be read. Auditing around them would
        # grade rules nobody saw, so any entry here makes the run NOT AUDITED.
        # Keyed by path: some scopes are read by more than one target.
        self.unread = {}

    def add(self, severity, layer, title, detail):
        self.findings.append((severity, layer, title, detail))

    def emit(self):
        order = {"HIGH": 0, "MED": 1, "LOW": 2, "OK": 3}
        self.findings.sort(key=lambda f: order.get(f[0], 9))
        width = 74
        print("\n" + "=" * width)
        print(" FINDINGS  (severity · ladder layer)")
        print("=" * width)
        for sev, layer, title, detail in self.findings:
            print("\n  [%-4s] %-12s %s" % (sev, layer, title))
            for line in detail.splitlines():
                print("           %s" % line)
        highs = sum(1 for f in self.findings if f[0] == "HIGH")
        print("\n" + "-" * width)
        print(" %d finding(s); %d HIGH" % (len(self.findings), highs))
        print("=" * width)
        return highs


# ===========================================================================
#  TARGET 1 · Claude Code  (L08)
# ===========================================================================

def audit_claude(r):
    print("\n### CLAUDE CODE ###")
    configs = inventory(r, SCOPES, load_json)
    print("\n  Reminder: permission rules MERGE across scopes; deny beats allow.")

    merged_allow, merged_deny, merged_ask = [], [], []
    for name in ("user", "project", "local", "managed"):
        merged_allow += rules(configs[name], "allow")
        merged_deny += rules(configs[name], "deny")
        merged_ask += rules(configs[name], "ask")

    audit_claude_modes(r, configs, merged_deny, merged_ask, merged_allow)

    # ---- THE SELF-MODIFICATION HOLE ---------------------------------------
    # An agent with Write/Edit can rewrite the file that constrains it, unless
    # something denies that. This is "never let the constrained party supply
    # the constraint" at the config layer.
    guards_own_config, inert_guards = file_rules(merged_deny, ["settings.json", ".claude/"])
    if guards_own_config:
        r.add("OK", "harness", "Settings files are deny-protected",
              "Rules matching: %s\nThe agent cannot rewrite its own constraints via Write/Edit."
              % ", ".join(map(str, guards_own_config[:3])))
    elif inert_guards:
        r.add("HIGH", "harness", "Settings are guarded by a rule that is never consulted",
              "Found: %s\n"
              "This rule LOOKS like the control and is inert: file access is\n"
              "checked against Edit(path) and Read(path) only. A path rule on\n"
              "Write, NotebookEdit, Glob or MultiEdit is accepted, warned about\n"
              "at startup, and never used. So the hole is open AND the config\n"
              "reads as if it were closed -- worse than having no rule.\n"
              "FIX: rewrite as Edit(.claude/settings*.json)."
              % ", ".join(map(str, inert_guards[:3])))
    else:
        r.add("HIGH", "harness", "Agent can edit the file that constrains it",
              "No deny rule covers .claude/settings*.json.\n"
              "Write/Edit are enabled by default, so the permission rules are\n"
              "attacker-writable — they fail the (b) half of the control test.\n"
              "Contrast: Codex closes this at the rung BELOW — its sandbox keeps\n"
              ".codex/ read-only even inside a writable root.\n"
              "FIX: deny \"Edit(.claude/settings*.json)\" — Edit covers EVERY built-in\n"
              "     editing tool. Do NOT write Write(...): a path rule on Write,\n"
              "     NotebookEdit, Glob or MultiEdit is accepted and never consulted.\n"
              "     Then managed settings / a PreToolUse hook for the rest.")

    # ---- leg ② — secret reads ---------------------------------------------
    protected, inert_secrets = file_rules(merged_deny, SECRET_TARGETS)
    if protected:
        r.add("OK", "harness", "Some secret paths are denied",
              "Rules matching: %s" % ", ".join(map(str, protected[:4])))
    elif inert_secrets:
        r.add("HIGH", "harness", "Secret paths guarded by rules that are never consulted",
              "Found: %s\nRewrite as Read(...) / Edit(...)."
              % ", ".join(map(str, inert_secrets[:4])))
    else:
        r.add("HIGH", "harness", "No deny rules on secret-bearing paths",
              "Nothing matches .env / .ssh / credentials / .aws.\n"
              "Leg ② (private data) is wide open to anything that reads files.\n"
              'FIX: deny "Read(./.env)", "Read(./.env.*)", "Read(~/.ssh/**)", '
              '"Read(~/.aws/**)".')

    # ---- leg ③ — egress ----------------------------------------------------
    # Same class as F8: mentions() here would count Read(./curl-notes.txt)
    # as an egress control. Bash rules only, matched on the command spec.
    egress_denied = command_rules(merged_deny, EGRESS_COMMANDS)
    egress_asked = command_rules(merged_ask, EGRESS_COMMANDS)
    if egress_denied or egress_asked:
        r.add("OK", "harness", "Some egress commands are gated",
              "deny: %s\nask : %s" % (egress_denied[:3] or "-", egress_asked[:3] or "-"))
    else:
        r.add("MED", "harness", "Outbound commands are ungated",
              "No deny/ask rule matches curl / wget / nc / scp.\n"
              "Leg ③ is open at the command layer. Note this is a DESTINATION\n"
              "problem: a rule per binary is a wrapper, not a choke point —\n"
              "the Environment-layer answer is an egress policy (L07 D2).")

    # ---- blanket allows ----------------------------------------------------
    blanket = [x for x in merged_allow if str(x).strip() in ("Bash(*)", "Bash", "*")]
    if blanket:
        r.add("HIGH", "harness", "Blanket allow defeats the rule set",
              "Found: %s\nThis pre-approves arbitrary shell. Deny rules still win,\n"
              "but everything not explicitly denied now runs unprompted."
              % ", ".join(map(str, blanket)))

    # ---- hooks -------------------------------------------------------------
    hooked = [n for n in ("user", "project", "local", "managed")
              if (configs[n] or {}).get("hooks", {}).get("PreToolUse")]
    if hooked:
        r.add("OK", "harness+", "PreToolUse hook(s) configured",
              "Scopes: %s\nHooks are deterministic code you own — strictly stronger\n"
              "than a pattern rule, because they can inspect the full tool input."
              % ", ".join(hooked))
    else:
        r.add("LOW", "harness+", "No PreToolUse hooks",
              "Pattern rules only. A hook can block on things a glob cannot express\n"
              "(command semantics, argument combinations, target host).")

    # ---- org layer ---------------------------------------------------------
    if configs["managed"]:
        m = configs["managed"]
        locked = [k for k in ("allowManagedPermissionRulesOnly",
                              "allowManagedHooksOnly",
                              "allowManagedMcpServersOnly") if m.get(k)]
        r.add("OK", "environment", "Managed settings present",
              "Lockdown flags set: %s\nThis is the only layer the local user — and so the agent — cannot edit."
              % (", ".join(locked) or "none"))
    else:
        r.add("MED", "environment", "No managed-settings layer (mode included: only managed can pin it)",
              "Every control lives in user/project/local files, all of which are\n"
              "editable by whoever (or whatever) can write to the filesystem.\n"
              "In an org setting, managed settings are the equivalent of the\n"
              "Environment layer: enforced below anything the agent can touch.\n"
              "Codex equivalent: /etc/codex/requirements.toml. Cursor equivalent:\n"
              "team-dashboard Run Mode policy (NOT visible from this client).")


# ---------------------------------------------------------------------------
#  L11 · THE SECOND AXIS — the permission MODE
#
#  L09 took two axes from Codex: the sandbox is what the agent CAN do, the
#  approvals setting is when it ASKS. Claude Code has the same pair and we only
#  ever audited one of them. Rules say what is allowed; the MODE decides what
#  happens to everything the rules did NOT decide. Same rules, different mode,
#  different enforcement — so a rules-only audit reports on a configuration
#  that does not exist.
#
#  Verified 2026-08-17, permission-modes reference.
# ---------------------------------------------------------------------------

MODE_LADDER = [
    # mode,              runs without asking,                protected-path write
    ("default/manual",   "reads only",                       "prompted"),
    ("acceptEdits",      "reads, edits, common fs commands", "prompted"),
    ("plan",             "reads + classifier-approved cmds", "prompted / classifier"),
    ("auto",             "everything, classifier reviews",   "routed to the CLASSIFIER"),
    ("dontAsk",          "only pre-approved tools",          "denied"),
    ("bypassPermissions", "everything",                      "ALLOWED"),
]

# Rule kinds that survive every mode, including bypassPermissions.
SURVIVES_EVERY_MODE = ("deny", "ask")


def audit_claude_modes(r, configs, merged_deny, merged_ask, merged_allow):
    print("\n  MODE LADDER · what the same rule set means in each mode")
    print("  " + "-" * 70)
    for mode, without_asking, protected in MODE_LADDER:
        print("  %-18s %-34s %s" % (mode, without_asking, protected))

    # ---- who sets the starting mode, and does it actually apply? ----------
    setters = [(n, (configs[n] or {}).get("permissions", {}).get("defaultMode"))
               for n in ("managed", "project", "local", "user")]
    setters = [(n, v) for n, v in setters if v]

    # The trap: "auto" in project/local is SILENTLY IGNORED, and it also stops
    # Claude Code falling back to a defaultMode from ~/.claude/settings.json.
    ignored = [(n, v) for n, v in setters if v == "auto" and n in ("project", "local")]
    if ignored:
        r.add("MED", "harness", "defaultMode \"auto\" set where it does not apply",
              "%s\nAn \"auto\" value in project or local settings does not take effect,\n"
              "and Claude Code then uses the BUILT-IN default rather than a\n"
              "defaultMode from ~/.claude/settings.json. So this line reads like a\n"
              "setting, changes nothing, and suppresses the one that would have.\n"
              "Same family as a Write(path) deny rule: accepted, never consulted."
              % "\n".join("  %s settings: defaultMode=%r" % (n, v) for n, v in ignored))

    effective = [(n, v) for n, v in setters if (n, v) not in ignored]
    if any(v == "bypassPermissions" for _, v in effective):
        r.add("HIGH", "harness", "bypassPermissions is the configured starting mode",
              "Everything runs unprompted and protected-path writes are ALLOWED —\n"
              "including writes to .claude/, i.e. the agent's own permission slip.\n"
              "Documented as being for isolated containers and VMs only.\n"
              "Survives it: deny and explicit ask rules. Nothing else you wrote.")
    elif effective:
        n, v = effective[0]
        r.add("OK", "harness", "Starting mode is pinned in config",
              "%s settings: defaultMode=%r (highest-precedence setter).\n"
              "An auditor can read this one off disk — which is the exception,\n"
              "not the rule. See the finding below." % (n, v))
    else:
        r.add("MED", "harness", "Starting mode is not pinned anywhere",
              "No permissions.defaultMode in any scope, so the BUILT-IN default\n"
              "applies. On Pro, Max and Team plans that is `auto`, where a second\n"
              "model — the classifier — reviews actions instead of you.\n"
              "It falls back to manual only if: disableAutoMode is set, feature-flag\n"
              "fetching is off, first session after install/upgrade, `claude -p` /\n"
              "the Agent SDK, or a Bedrock/Vertex/Foundry/gateway session.\n"
              "So the mode depends on your PLAN, VERSION and NETWORK — none of\n"
              "which are in this repository.\n"
              "FIX: pin it. permissions.defaultMode in managed or user settings.")

    # ---- the kill switch ---------------------------------------------------
    disabled = [n for n in ("managed", "project", "local", "user")
                if (configs[n] or {}).get("permissions", {}).get("disableAutoMode") == "disable"]
    if disabled:
        r.add("OK", "harness", "Auto mode is disabled",
              "Set in: %s\nNo classifier in the enforcement path; every ungoverned\n"
              "action reaches a human instead of a model." % ", ".join(disabled))
    elif "managed" not in [n for n, _ in effective]:
        r.add("LOW", "harness", "Auto mode is selectable",
              "permissions.disableAutoMode is not set to \"disable\" anywhere, so a\n"
              "user (or anything that can write settings) can switch into a mode\n"
              "where an LLM decides what your rules did not.\n"
              "Only managed settings can take that choice away org-wide.")

    # ---- which of your rules survive a mode change? ------------------------
    r.add("OK" if merged_deny or merged_ask else "MED", "harness",
          "Mode-durable rules: %d deny, %d ask (allow: %d, void under bypass)"
          % (len(merged_deny), len(merged_ask), len(merged_allow)),
          "Deny rules and explicit ask rules apply in EVERY mode, including\n"
          "bypassPermissions. Allow rules have no effect there — everything is\n"
          "already approved. So protection built out of allow rules is\n"
          "MODE-DEPENDENT, and protection built out of deny rules is not.\n"
          "The vendor states the principle for conversational limits too:\n"
          "\"Boundaries are not stored as rules... For a hard guarantee, add a\n"
          "deny rule instead.\"")

    # ---- the finding a static auditor must always emit --------------------
    r.add("LOW", "harness", "Runtime mode is UNKNOWABLE from disk",
          "The mode of a RUNNING session is not in any config file. Shift+Tab\n"
          "changes it mid-session; --permission-mode overrides settings; a resumed\n"
          "session keeps whatever it had. This audit reads the STARTING inputs.\n"
          "This is a class of control state that config auditing cannot reach —\n"
          "worth saying out loud in any report, because a clean audit here does\n"
          "not describe the session someone is actually running.")


# ===========================================================================
#  TARGET 2 · Codex CLI  (L09)
# ===========================================================================

def codex_effective(configs, key, default=None):
    """First value found in precedence order project > user > system."""
    for name in ("project", "user", "system"):
        cfg = configs.get(name) or {}
        if key in cfg:
            return cfg[key], name
    return default, "unset"


def audit_codex(r):
    print("\n### CODEX CLI ###")
    configs = inventory(r, CODEX_SCOPES, load_toml)
    reqs, req_err = load_toml(CODEX_REQUIREMENTS)
    if req_err:
        r.unread[str(CODEX_REQUIREMENTS)] = req_err
    print("  %-9s %-38s %s" % ("managed", str(CODEX_REQUIREMENTS)[-38:],
                               req_err or ("found" if reqs is not None else "absent")))
    print("\n  Reminder: sandbox_mode = what it CAN do; approval_policy = when it ASKS.")

    if all(v is None for v in configs.values()) and reqs is None:
        r.add("LOW", "—", "Codex: no config found",
              "Nothing at ~/.codex/config.toml, .codex/config.toml or /etc/codex/.\n"
              "Codex then runs on built-in defaults (documented as workspace-write\n"
              "sandbox + approval prompts). Absence of config is not absence of\n"
              "policy here — unlike Claude Code, the floor is an OS sandbox.")
        return

    sandbox, sb_scope = codex_effective(configs, "sandbox_mode")
    approval, ap_scope = codex_effective(configs, "approval_policy")

    # ---- the sandbox rung ---------------------------------------------------
    if sandbox == "danger-full-access":
        r.add("HIGH", "environment", "Codex sandbox disabled (danger-full-access)",
              "Set in the %s scope. Docs: 'the agent runs without sandbox\n"
              "restrictions. This removes the filesystem and network boundaries.'\n"
              "Two consequences, not one: leg ③ egress is unconstrained, AND the\n"
              "protection that keeps .codex/ read-only goes with it — so Codex\n"
              "inherits the same self-modification hole as an ungated Claude Code."
              % sb_scope)
    elif sandbox == "read-only":
        r.add("OK", "environment", "Codex sandbox: read-only",
              "Set in the %s scope. Strongest documented posture: edits and\n"
              "commands require approval. Platform-native enforcement (Seatbelt on\n"
              "macOS) — an Environment-rung control, not an in-process check." % sb_scope)
    else:
        r.add("OK", "environment", "Codex sandbox: workspace-write (%s)" % sb_scope,
              "Writes confined to the workspace by a platform sandbox — the rung\n"
              "Claude Code has no equivalent of. Documented as keeping protected\n"
              "control dirs (.git, .codex, .agents) read-only even when their\n"
              "parent root is writable.\n"
              "VERIFY, do not trust the prose: run the falsification case —\n"
              "ask Codex to append a line to .codex/config.toml under this mode.\n"
              "If it succeeds, this OK is a HIGH.")

    # ---- the approvals rung -------------------------------------------------
    if approval == "never":
        sev = "HIGH" if sandbox == "danger-full-access" else "MED"
        r.add(sev, "harness", "Codex approvals disabled (approval_policy = never)",
              "Set in the %s scope. No human gate remains; the sandbox is the ONLY\n"
              "thing standing between an injected plan and your machine.\n"
              "Rule of Two reading: with legs ① and ② present, the third must be\n"
              "gated by something. 'never' + a sandbox = one control, no gate."
              % ap_scope)
    elif approval in ("untrusted", "on-request") or isinstance(approval, dict):
        r.add("OK", "harness", "Codex approvals: %s (%s)" % (approval, ap_scope),
              "A human gate exists. Note it is a HARNESS-rung control: it can be\n"
              "flipped by anything that can write ~/.codex/config.toml, unless a\n"
              "requirements.toml pins it.")
    else:
        r.add("LOW", "harness", "Codex approval_policy unset",
              "Falls back to the built-in default. Do not assume which one —\n"
              "read it off the session banner rather than from memory.")

    # ---- leg ③ at the sandbox layer ----------------------------------------
    ww = {}
    for name in ("project", "user", "system"):
        ww.update((configs.get(name) or {}).get("sandbox_workspace_write", {}) or {})
    net = ww.get("network_access")
    if net in (True, "allowed", "enabled"):
        r.add("MED", "environment", "Codex workspace-write has network access ON",
              "[sandbox_workspace_write] network_access = %r.\n"
              "This is the cleanest egress switch any of these agents exposes, and\n"
              "it is currently open: leg ③ needs no curl, just any process the\n"
              "agent starts. Turning it off is the L07-Day-2 egress control, one\n"
              "line, enforced below the tool." % (net,))
    elif net in (False, "blocked", "disabled"):
        r.add("OK", "environment", "Codex network access blocked in workspace-write",
              "network_access = %r — leg ③ severed at the Environment rung.\n"
              "This is the same control you built by hand in L07 D2, shipped." % (net,))
    roots = ww.get("writable_roots") or []
    if roots:
        r.add("LOW", "environment", "Codex writable_roots extends the sandbox",
              "%d extra root(s) configured. Each one widens the blast radius of a\n"
              "hijacked plan. Protected control dirs stay read-only inside them —\n"
              "but only while the sandbox is on." % len(roots))

    # ---- leg ① --------------------------------------------------------------
    features = {}
    for name in ("project", "user", "system"):
        features.update((configs.get(name) or {}).get("features", {}) or {})
    ws, _ = codex_effective(configs, "web_search")
    if ws is True or features.get("web_search"):
        r.add("LOW", "model", "Codex web search enabled",
              "Docs: 'Prompt injection can cause the agent to fetch and follow\n"
              "untrusted instructions.' This is leg ① wired in on purpose. Not a\n"
              "misconfiguration — just a leg you now owe a gate for.")

    # ---- org layer ----------------------------------------------------------
    if reqs is not None:
        r.add("OK", "environment", "Codex managed requirements present",
              "/etc/codex/requirements.toml constrains security-sensitive settings\n"
              "(approval policy, sandbox mode, profiles, hooks, MCP servers).\n"
              "Docs: on conflict 'the local client falls back to a compatible\n"
              "value and notifies the user' — users cannot override it.")
    else:
        r.add("MED", "environment", "Codex has no managed requirements layer",
              "sandbox_mode and approval_policy live in files you (and anything\n"
              "running as you) can edit. requirements.toml is the rung that puts\n"
              "them out of reach. Same finding as Claude Code's missing managed\n"
              "settings — different filename, identical ladder position.")

    # ---- project trust ------------------------------------------------------
    r.add("LOW", "harness", "Codex-specific: project trust gates project config",
          "Docs: 'If you mark a project as untrusted, Codex skips project-scoped\n"
          ".codex/ layers, including project-local config, hooks, and rules.'\n"
          "Read that in both directions — trusting a repo you cloned hands its\n"
          ".codex/config.toml a vote on your sandbox. Untrusted-by-default is the\n"
          "supply-chain posture (ASI04).")


# ===========================================================================
#  TARGET 3 · Cursor  (L09)
# ===========================================================================

def audit_cursor(r):
    print("\n### CURSOR ###")
    configs = inventory(r, CURSOR_SCOPES, load_json)
    print("\n  Reminder: allowlist model only — Cursor exposes no tool DENY list.")

    merged = {"mcpAllowlist": [], "terminalAllowlist": []}
    autorun = {}
    for name in ("user", "workspace"):
        cfg = configs.get(name) or {}
        for k in merged:
            merged[k] += cfg.get(k, []) or []
        autorun.update(cfg.get("autoRun", {}) or {})

    # ---- the structural finding, true regardless of config -----------------
    r.add("MED", "model", "Cursor's default gate has a model in the enforcement path",
          "Docs describe Auto-review as the default Run Mode: it runs allowlisted\n"
          "calls, sandboxes shell commands when it can, and routes the rest\n"
          "through an LLM classifier returning allow or block.\n"
          "Two-property test: property (a) says a control is not LLM-mediated.\n"
          "A classifier gate fails (a) by construction — it is a MITIGATION on the\n"
          "ladder, not a control. Cursor says so itself: the run modes are\n"
          "'best-effort guardrails rather than a hard security boundary.'")

    if configs["user"] is None and configs["workspace"] is None:
        r.add("LOW", "—", "Cursor: no permissions.json",
              "Default posture applies: 'By default, terminal commands need your\n"
              "approval', and every MCP connection plus each individual tool call\n"
              "needs approval. Nothing is pre-approved — the safest state, and the\n"
              "one users disable first for convenience.")
    else:
        r.add("LOW", "harness", "Cursor permissions.json present",
              "Note the merge rule differs from Claude Code's: per-user and\n"
              "per-repo arrays CONCATENATE, and a key defined in the file REPLACES\n"
              "the in-app allowlist entirely. Know which of the two you edited.")

    if merged["terminalAllowlist"]:
        r.add("MED", "harness", "Cursor terminal allowlist pre-approves %d prefix(es)"
              % len(merged["terminalAllowlist"]),
              "Matching is prefix-based over a shell string, which makes it a\n"
              "PARSER, not a boundary. Evidence, not theory: CVE-2026-22708\n"
              "(GHSA-82wg-qcm4-fp2w, Cursor <=2.2, fixed 2.3) — shell built-ins\n"
              "and environment-variable poisoning ran without appearing in the\n"
              "allowlist or prompting. Docs concede: 'The allowlist is best-effort,\n"
              "not a security boundary. Determined agents or prompt injection\n"
              "might bypass it.'")

    wild = [x for x in merged["mcpAllowlist"] if "*" in str(x)]
    if wild:
        r.add("MED", "harness", "Cursor MCP allowlist contains wildcards",
              "Entries: %s\nA `server:*` entry pre-approves every tool that server\n"
              "exposes now AND every tool it adds later — the tool-list drift you\n"
              "flagged in L04. Enumerate the tools you actually need."
              % ", ".join(map(str, wild[:4])))

    if autorun.get("block_instructions") or autorun.get("allow_instructions"):
        r.add("MED", "model", "Cursor autoRun instructions are prompt text, not rules",
              "allow_instructions / block_instructions steer the Auto-review\n"
              "classifier. They are English sentences fed to a model — the exact\n"
              "thing L07 Variant 1 graded as NOT a control. Useful; not a gate.")

    if Path(".cursorignore").exists():
        r.add("OK", "harness", ".cursorignore present in this project",
              "Blocks agent access to listed files — the closest thing Cursor has\n"
              "to a leg-② deny rule. Verify it covers .env and key material.")
    else:
        r.add("LOW", "harness", "No .cursorignore in this project",
              "Cursor has no path deny-list otherwise; .cursorignore is the lever.")

    r.add("LOW", "environment", "Cursor's org rung is invisible from here",
          "Team-admin Run Mode policy is set in the dashboard and, per the docs,\n"
          "'Neither permissions.json nor the IDE allowlist can add extra entries.'\n"
          "That makes it the strongest rung — and unauditable from the client.\n"
          "An audit finding in itself: you cannot verify your own enforcement.")


# ===========================================================================
#  TARGET 4 · an agent YOU wrote  (L09)
# ===========================================================================

def audit_harness(r, directory):
    """Audit source, not config. For an agent you wrote, the policy IS the code.

    LIMITS (read before believing any finding below):
      * This is a syntactic AST + NAME heuristic — the same class of signal as
        the L03 keyword baseline, with the same failure modes. It sees the SHAPE
        of a call graph, never its semantics.
      * It cannot follow indirection: a callable passed in, a dict of handlers,
        getattr dispatch, or a gate imported under an alias all defeat it.
      * A function containing the word `enforce` passes, whether or not it
        enforces anything. Naming is not evidence.
      * So: treat every finding as a POINTER TO READ A FUNCTION, never as a
        verdict. The verdict comes from redteam_bypass.py actually failing.
    """
    print("\n### YOUR OWN HARNESS · %s ###" % directory)
    d = Path(directory)
    if not d.is_dir():
        r.add("LOW", "—", "No harness directory at %s" % directory,
              "Nothing to audit. Pass --harness-dir to point at your agent source.")
        return

    files = sorted(p for p in d.glob("*.py"))
    print("\n  %d python file(s): %s" % (len(files), ", ".join(p.name for p in files)))
    print("  Heuristic: functions that reach a transport without naming a gate.")

    unguarded, guarded = [], []
    for p in files:
        try:
            tree = ast.parse(p.read_text())
        except (SyntaxError, PermissionError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            calls = [n for n in ast.walk(node)
                     if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                     and any(h in n.func.attr.lower() for h in TRANSPORT_HINTS)]
            if not calls:
                continue
            # IDENTIFIERS ONLY. v1 of this check dumped the whole AST, which
            # includes docstrings — so notify_webhook (the L07 D2 bypass) passed
            # because its docstring *mentions* ALLOWED_RECIPIENTS. Prose is not
            # enforcement; a heuristic that reads prose grades prose.
            names = set()
            for n in ast.walk(node):
                if isinstance(n, ast.Name):
                    names.add(n.id.lower())
                elif isinstance(n, ast.Attribute):
                    names.add(n.attr.lower())
                elif isinstance(n, ast.arg):
                    names.add(n.arg.lower())
                elif isinstance(n, ast.keyword) and n.arg:
                    names.add(n.arg.lower())
            where = "%s:%s:%d" % (p.name, node.name, node.lineno)
            if any(h in nm for nm in names for h in GATE_HINTS):
                guarded.append(where)
            else:
                unguarded.append(where)

    if unguarded:
        r.add("MED", "harness", "%d path(s) reach the transport naming no gate"
              % len(unguarded),
              "%s\nThis is the L07 Day-2 shape: the control lives in a SIBLING\n"
              "function, so it protects the paths someone remembered to wrap.\n"
              "Read each one and ask whether it can be called with an\n"
              "attacker-chosen destination." % "\n".join(unguarded))
    if guarded:
        r.add("OK", "harness", "%d path(s) reference a gate before the transport"
              % len(guarded), "\n".join(guarded) + "\nName-level signal only — read them.")

    src_all = "\n".join(p.read_text() for p in files if p.is_file())
    if "egress_allowlist" in src_all or "EgressBlocked" in src_all:
        r.add("OK", "environment", "An egress choke point exists below the tools",
              "The transport itself refuses non-allowlisted destinations, so an\n"
              "unwrapped sibling tool does not get a free exfil path. This is the\n"
              "rung that made L07 D2 hold.")
    else:
        r.add("HIGH", "environment", "No egress choke point in the transport",
              "Every control here is per-function. Add the check inside the thing\n"
              "being protected, or put an allow-list under it — otherwise finding\n"
              "1 is a permanent bug class rather than a bug.")

    redteams = [p for p in files if p.name.startswith("redteam")]
    falsifiable = [p.name for p in redteams
                   if "falsif" in p.read_text().lower() or "enforce=False" in p.read_text()]
    if not redteams:
        r.add("HIGH", "harness+", "No red-team eval alongside the harness",
              "For an agent you wrote, the audit has no config file to read — the\n"
              "eval IS the audit. Without one, every claim above is prose.")
    elif falsifiable:
        r.add("OK", "harness+", "Eval ships a falsification case",
              "Files: %s\nDisabling the control flips the verdict, so a PASS means\n"
              "the control caused it. This is the standard you set in L07."
              % ", ".join(falsifiable))
    else:
        r.add("MED", "harness+", "Red-team eval with no visible falsification case",
              "Files: %s\nA green eval that never inverts its control is asserting\n"
              "an outcome it did not test. Add the disable-the-control run and\n"
              "confirm it FAILS." % ", ".join(p.name for p in redteams))

    print("\n  LIMITS of this pass: AST + name matching. It finds SHAPE, not")
    print("  semantics; indirection defeats it; a function named `enforce` passes")
    print("  whether or not it enforces. Findings are pointers to read code.")


# ===========================================================================

LADDER = """
 LADDER PLACEMENT — the portable version:
   system prompt / rules files   -> NOT a control (injection argues past it)
   LLM classifier gate           -> MITIGATION (fails property (a): LLM-mediated)
   pattern rules / allow-lists   -> Harness  (deterministic, but config-writable)
   hooks / in-process checks     -> Harness+ (your code, full input)
   OS sandbox, egress policy     -> Environment (below what the agent can edit)
   managed settings / requirements.toml / team policy
                                 -> Environment (the local user cannot override)
"""

PORTABLE_SIX = """
 THE SIX QUESTIONS (ask them of any agent, this or the next one):
   1. Where does policy live — and can the agent write there?      (property b)
   2. Is anything in the enforcement path LLM-mediated?            (property a)
   3. What is the posture if I configure nothing at all?
   4. Which rung actually enforces it — prompt / harness / environment?
   5. Is there a rung above me that I cannot reach or edit?
   6. What does the VENDOR claim it is — boundary, or best effort?
"""


# ===========================================================================
#  TARGET 5 · The environment surface  (L14)
#
#  Every control this workspace has built is PATH-SHAPED: Read(./.env),
#  Edit(path), the hook's protected paths, sandbox filesystem.denyRead. Leg (2)
#  has two other shapes that no path rule reaches:
#
#    * VALUES IN THE ENVIRONMENT. "Sandboxed Bash commands inherit the parent
#      process environment by default, including any credentials set there."
#      A Read deny on ~/.aws/credentials says nothing about AWS_SECRET_ACCESS_KEY.
#    * CAPABILITY HANDLES. SSH_AUTH_SOCK is not a key; it is a socket to an
#      agent holding keys. A process that inherits it can make the agent SIGN
#      without ever reading ~/.ssh. Protecting the bytes does not protect the
#      capability.
#
#  Controls, and their exact reach (sandboxing reference, verified 2026-09-14):
#    sandbox.credentials.envVars mode:"deny"  -> unset before each SANDBOXED
#        command. Merges across scopes and only ever narrows: "any scope can
#        add one, but no scope can remove one that another scope added."
#    sandbox.credentials.envVars mode:"mask"  -> the command sees a sentinel;
#        the proxy swaps the real value in for injectHosts. Needs
#        network.tlsTerminate, and each injectHost must also be in
#        network.allowedDomains.
#    CLAUDE_CODE_SUBPROCESS_ENV_SCRUB          -> "strip credentials from all
#        subprocesses regardless of sandboxing" -- the only one of the three
#        that does not depend on the sandbox being on.
#
#  And the reason this function has to exist at all:
#      "There is no built-in credential deny list, so only the files and
#       variables you list are restricted."
#  An enumeration sitting inside the containment control. So: enumerate well.
#
#  THIS FUNCTION NEVER READS A VALUE. It reads os.environ.keys() only, and
#  prints names. A security tool that reads secrets is itself a leg-(2) target;
#  keeping it value-blind is the whole of its threat model.
# ===========================================================================

CRED_NAME = re.compile(
    r"(TOKEN|SECRET|KEY|PASSWORD|PASSWD|CREDENTIAL|_AUTH|APIKEY|API_KEY)", re.I)

# Names that match the pattern but are not credentials. Each one is a false
# positive this tool produced on a real machine and had to be taught about.
CRED_NOISE = {
    "CLAUDE_CODE_SESSION_ID", "CLAUDE_CODE_CHILD_SESSION",
    "CLAUDE_CODE_SESSION_ATTENDED", "SECURITYSESSIONID",
    "STARSHIP_SESSION_KEY", "TERM_SESSION_ID", "SSH_AUTH_SOCK",
}

# Handles: not secrets, but grants. A path rule cannot touch these.
HANDLES = {
    "SSH_AUTH_SOCK": "ssh-agent socket — an inheriting process can make the "
                     "agent SIGN with keys it can never read. A Read(~/.ssh/**) "
                     "deny does not touch this.",
    "DOCKER_HOST": "docker endpoint — the docs' own escalation example: access "
                   "to the socket 'effectively grants access to the host system'.",
    "GPG_AGENT_INFO": "gpg-agent socket — signing capability without the key.",
    "KUBECONFIG": "cluster credentials by reference; the file rule is on the "
                  "path this points AT, which may not be one you listed.",
}


def audit_env_surface(r):
    print("\n### ENVIRONMENT SURFACE ###\n")
    print("  Reading variable NAMES only. No value is read, printed or stored.")

    names = set(os.environ)

    # WHOSE environment? This is the part that makes the result reproducible.
    # The surface is per-PROCESS, not per-machine: a subprocess sees whatever
    # its parent handed down. Run from inside an agent session you measure the
    # agent's environment (the one its own Bash commands inherit -- the number
    # that matters for agent security). Run from your own terminal you measure
    # your shell. Same tool, same machine, different answer, and the difference
    # is the finding, not noise.
    agent_markers = sorted(n for n in names if n.startswith(("CLAUDE_CODE_", "CLAUDECODE")))
    inside_agent = bool(agent_markers)
    print("\n  MEASURING: %s"
          % ("this AGENT session's environment -- what its Bash subprocesses inherit"
             if inside_agent else "a plain shell's environment -- NOT what the agent's commands see"))
    print("  parent pid %s, %d variables. %s"
          % (os.getppid(), len(names),
             ("agent markers present: " + ", ".join(agent_markers[:3])
              + ("…" if len(agent_markers) > 3 else ""))
             if inside_agent else "no agent markers -- run this from inside the agent to compare."))
    if not inside_agent:
        print("  NOTE: a clean result here does NOT mean the agent's subprocesses")
        print("        are clean. Audit the environment the agent actually has.")
    declared_deny, declared_mask, scopes_seen = set(), set(), []
    for label, path, _ in SCOPES:
        cfg, err = load_json(path)
        if err:
            r.unread[str(path)] = err
        if not cfg:
            continue
        creds = ((cfg.get("sandbox") or {}).get("credentials") or {})
        for e in creds.get("envVars", []) or []:
            if not isinstance(e, dict):
                continue
            (declared_mask if e.get("mode") == "mask" else declared_deny).add(e.get("name"))
            scopes_seen.append(label)

    scrub = os.environ.get("CLAUDE_CODE_SUBPROCESS_ENV_SCRUB")
    candidates = sorted(n for n in names if CRED_NAME.search(n) and n not in CRED_NOISE)
    handles = sorted(n for n in names if n in HANDLES)

    print("\n  %d variables in this process; %d credential-shaped; %d handle(s)."
          % (len(names), len(candidates), len(handles)))
    print("  Suppressed as known-noise: %s"
          % ", ".join(sorted(n for n in names if n in CRED_NOISE)) or "none")

    print("\n  CREDENTIAL-SHAPED NAMES")
    print("  " + "-" * 70)
    uncovered = []
    if not candidates:
        print("  (none)")
    for n in candidates:
        if n in declared_deny:
            state = "deny declared  (sandboxed commands only)"
        elif n in declared_mask:
            state = "mask declared  (needs tlsTerminate + allowedDomains)"
        elif scrub:
            state = "scrubbed       (SUBPROCESS_ENV_SCRUB, all subprocesses)"
        else:
            state = "UNPROTECTED"
            uncovered.append(n)
        print("  %-38s %s" % (n, state))

    print("\n  CAPABILITY HANDLES · not secrets, and no path rule reaches them")
    print("  " + "-" * 70)
    for n in handles:
        covered = n in declared_deny or n in declared_mask or scrub
        print("  %-38s %s" % (n, "protected" if covered else "INHERITED BY SUBPROCESSES"))
        print("      %s" % HANDLES[n])

    if uncovered:
        r.add("HIGH", "environment", "Credential-shaped env vars reach every subprocess",
              "Unprotected: %s\n"
              "Sandboxed commands 'inherit the parent process environment by\n"
              "default, including any credentials set there', and there is NO\n"
              "built-in credential deny list -- only what you enumerate.\n"
              "FIX: sandbox.credentials.envVars with mode 'deny' (sandboxed\n"
              "     commands) or 'mask' (keeps the tool working); or\n"
              "     CLAUDE_CODE_SUBPROCESS_ENV_SCRUB for ALL subprocesses,\n"
              "     which is the only one that does not need the sandbox on."
              % ", ".join(uncovered))

    unguarded_handles = [n for n in handles
                         if not (n in declared_deny or n in declared_mask or scrub)]
    if unguarded_handles:
        r.add("MED", "environment", "Capability handles inherited by every subprocess",
              "%s\n"
              "These are not secrets, so no Read/Edit deny rule and no\n"
              "filesystem.denyRead touches them. They hand a subprocess the USE\n"
              "of a credential without its bytes.\n"
              "UNKNOWN, and worth one experiment: whether the sandbox blocks the\n"
              "socket itself by default. The docs discuss allowUnixSockets as an\n"
              "escalation risk but do not state the default. Test, do not assume."
              % ", ".join(unguarded_handles))

    if not scrub:
        r.add("LOW", "environment", "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB not set",
              "The only env control that applies whether or not the sandbox is on.\n"
              "Unset here. Note the trade: it strips credentials from ALL\n"
              "subprocesses, so tools that legitimately authenticate will break.\n"
              "That is an argument for per-variable 'mask', not against scrubbing.")


# ===========================================================================
#  SELF-TEST · pins the F8 family so it cannot silently come back
#
#  Every case below is a verdict this tool actually got wrong on 2026-09-17,
#  or the control case proving the fix did not overcorrect. Offline, no config.
# ===========================================================================

RULE_CASES = [
    # (rules, needles, kind, expect_consulted, expect_inert, note)
    (["Write(.claude/settings*.json)"], ["settings.json", ".claude/"], "file",
     0, 1, "F8: L08's own prescription is INERT, not protection"),
    (["Edit(.claude/settings*.json)"], ["settings.json", ".claude/"], "file",
     1, 0, "the rule that actually works"),
    (["Read(.claude/settings.json)"], ["settings.json"], "file",
     1, 0, "Read deny also blocks Edit and Write on the path"),
    (["NotebookEdit(.claude/settings.json)"], ["settings.json"], "file",
     0, 1, "inert, same family as Write"),
    (["Write"], ["settings.json"], "file",
     1, 0, "bare tool-name deny matches at tool level -- real"),
    (["WebFetch(domain:credentials.example.com)"], SECRET_TARGETS, "file",
     0, 0, "F8b: an egress allow rule is not a secret-path deny"),
    (["Read(~/.ssh/**)"], SECRET_TARGETS, "file",
     1, 0, "the real thing"),
    (["Bash(cat .env)"], SECRET_TARGETS, "file",
     0, 0, "a Bash rule is not a file path rule"),
    (["Read(./curl-notes.txt)"], EGRESS_COMMANDS, "cmd",
     0, 0, "F8c: a filename containing 'curl' is not an egress control"),
    (["Bash(curl *)"], EGRESS_COMMANDS, "cmd",
     1, 0, "the real thing"),
    (["Bash(wget *)"], EGRESS_COMMANDS, "cmd",
     1, 0, "control"),
    (["Edit(docs/**)"], ["settings.json"], "file",
     0, 0, "non-matching path stays out"),
]


def self_test():
    print("=" * 74)
    print(" SELF-TEST · rule matching (pins the F8 substring family)")
    print("=" * 74)
    bad = 0
    for rules_, needles, kind, want_c, want_i, note in RULE_CASES:
        if kind == "file":
            c, i = file_rules(rules_, needles)
        else:
            c, i = command_rules(rules_, needles), []
        ok = (len(c) == want_c and len(i) == want_i)
        bad += not ok
        print("  %-5s %-34s -> %d consulted / %d inert   %s"
              % ("PASS" if ok else "FAIL", rules_[0][:34], len(c), len(i), note))
    print("\n %d/%d pass" % (len(RULE_CASES) - bad, len(RULE_CASES)))
    print("\n The eval this file vouches for is checked by RUNNING it, not by")
    print(" grepping for the word 'falsif' -- see X1. redteam_stepup.py's own")
    print(" --falsify run must flip the verdict; it did not until 2026-09-17.")
    return bad


@_cli.entrypoint
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", default=".", help="project dir containing .claude/ etc.")
    ap.add_argument("--agent", default="claude",
                    choices=["claude", "codex", "cursor", "harness", "env", "all"],
                    help="which agent to audit (default: claude)")
    ap.add_argument("--harness-dir", default="harness", help="source dir for --agent harness")
    ap.add_argument("--self-test", action="store_true",
                    help="run the offline rule-matching test suite and exit")
    args = ap.parse_args()
    if args.self_test:
        return 1 if self_test() else 0
    _cli.chdir_project(args.project)

    print("=" * 74)
    print(" CODING-AGENT CONFIG AUDIT · Rule of Two applied to your own workflow")
    print(" project: %s   target: %s" % (Path.cwd(), args.agent))
    print("=" * 74)

    r = Report()
    if args.agent in ("claude", "all"):
        audit_claude(r)
    if args.agent in ("codex", "all"):
        audit_codex(r)
    if args.agent in ("cursor", "all"):
        audit_cursor(r)
    if args.agent in ("harness", "all"):
        audit_harness(r, args.harness_dir)
    if args.agent in ("env", "all"):
        audit_env_surface(r)

    highs = r.emit()
    print(LADDER)
    print(PORTABLE_SIX)
    print(" VERIFIED 2026-08-17 (permission-modes reference): deny rules and")
    print(" explicit ask rules apply in EVERY mode, INCLUDING bypassPermissions.")
    print(" Allow rules have no effect there. So the one control with a documented")
    print(" guarantee across every mode is a DENY RULE.")
    print(" VERIFIED 2026-08-25 (Agent SDK permission flow), superseding the note that")
    print(" stood here: hooks run FIRST, and a hook deny applies even in")
    print(" bypassPermissions. A hook allow never clears a deny or ask rule, so the")
    print(" hook is a one-way ratchet. Hold both -- but not because the hook's mode")
    print(" durability is unknown; it isn't. Deny rules earn their place by beating")
    print(" a hook ALLOW.")
    if r.unread:
        raise _cli.NotAudited(
            "%d config file(s) exist but could not be read, so the findings\n"
            "       above describe rules this audit never saw:\n%s"
            % (len(r.unread), "\n".join("         %s: %s" % pe for pe in r.unread.items())))
    return 1 if highs else 0


if __name__ == "__main__":
    sys.exit(main())
