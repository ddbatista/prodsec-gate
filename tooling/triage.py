#!/usr/bin/env python3
"""
agent-triage — a static reviewer for agentic systems.

Reads an agent manifest (JSON), tags each tool with the trifecta legs it
introduces, applies the Rule of Two (+ an irreversibility override), and maps
findings to the OWASP Top 10 for Agentic Applications (2026).

This is the automated successor to the manual Agent Security-Review Checklist
(reference/agent-security-review-checklist.html). v0.1.

Usage:
    python3 triage.py [manifest.json]
    python3 triage.py sample-agent.json

Exit code: 0 = SHIP, 1 = GATE/violation (so it can fail a CI pipeline).

Frameworks:
  - Lethal Trifecta .... Willison (2025)
  - Rule of Two ........ Meta (2026)
  - Four-layer model ... Anthropic, "Trustworthy Agents in Practice" (2026)
  - OWASP Agentic Top 10 (ASI) ... OWASP GenAI Security Project (2026)
"""
import json
import sys

# --- The capability vocabulary a manifest may use, mapped to trifecta legs ----
# A tool declares "capabilities". We fold them into the three Rule-of-Two legs.
LEG1 = "untrusted_input"      # ① attacker-influenceable content reaches the agent
LEG2 = "private_data"         # ② can read secrets / sensitive systems
# ③ = state_change OR external_comms (Meta's third leg is broader than exfil)
LEG3_CAPS = {"external_comms", "state_change"}

VALID_CAPS = {LEG1, LEG2, "external_comms", "state_change", "persistent_memory"}

# --- OWASP Top 10 for Agentic Applications (2026), verified against ----------
# genai.owasp.org and promptfoo.dev/docs/red-team/owasp-agentic-ai
OWASP = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse & Exploitation",
    "ASI03": "Identity & Privilege Abuse",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory & Context Poisoning",
}


def load(path):
    if path == "-":               # read a piped manifest from stdin
        return json.load(sys.stdin)
    with open(path) as f:
        return json.load(f)


def tag_legs(tools):
    """Return (leg1, leg2, leg3) booleans aggregated across the session."""
    caps = set()
    for t in tools:
        caps.update(t.get("capabilities", []))
    leg1 = LEG1 in caps
    leg2 = LEG2 in caps
    leg3 = bool(caps & LEG3_CAPS)
    return leg1, leg2, leg3


def irreversible_actions(tools):
    """Tools that mutate state and are declared non-reversible."""
    out = []
    for t in tools:
        caps = set(t.get("capabilities", []))
        if "state_change" in caps and t.get("reversible", True) is False:
            out.append(t["name"])
    return out


def unscoped_privileged(tools):
    """Privileged tools with no declared scope/least-privilege → ASI03 smell."""
    out = []
    for t in tools:
        caps = set(t.get("capabilities", []))
        privileged = caps & ({LEG2} | LEG3_CAPS)
        if privileged and not t.get("scope"):
            out.append(t["name"])
    return out


def assess(m):
    tools = m.get("tools", [])
    leg1, leg2, leg3 = tag_legs(tools)
    legs = [b for b in (leg1, leg2, leg3) if b]
    count = len(legs)
    hil = m.get("human_in_loop", False)
    irrev = irreversible_actions(tools)
    unscoped = unscoped_privileged(tools)

    findings = []  # (severity, ASI, message)

    # Rule of Two
    if count == 3:
        findings.append(("HIGH", "ASI01",
            "Full lethal trifecta (①+②+③): one poisoned input can read secrets "
            "and exfiltrate them. Rule-of-Two violation."))
        findings.append(("HIGH", "ASI02",
            "Trifecta enables tool-driven exfiltration via the egress/state leg."))
    if irrev:
        findings.append(("HIGH", "ASI02",
            "Irreversible state-change without recovery: " + ", ".join(irrev) +
            ". Impact/reversibility override the leg count."))
    if leg1:
        findings.append(("MED", "ASI01",
            "Untrusted content reaches the agent → goal-hijack surface. "
            "Confirm provenance ('internal' is not 'trusted')."))
    if unscoped:
        findings.append(("MED", "ASI03",
            "Privileged tool(s) without action-level scope: " + ", ".join(unscoped) +
            ". Apply least privilege at the action, scope/expire tokens."))
    for t in tools:
        if "state_change" in t.get("capabilities", []) and "exec" in t["name"].lower():
            findings.append(("MED", "ASI05",
                "Tool '%s' may run code/commands → unexpected code execution." % t["name"]))
        if "persistent_memory" in t.get("capabilities", []) and "untrusted_input" in t.get("capabilities", []):
            findings.append(("MED", "ASI06",
                "Tool '%s' writes untrusted content into persistent memory → "
                "memory/context poisoning across sessions." % t["name"]))

    # Verdict
    blocking = count == 3 or bool(irrev)
    if blocking and not hil:
        verdict = "GATE"  # not shippable autonomously
    elif blocking and hil:
        verdict = "SHIP*"  # acceptable only because a human gates it
    elif count <= 2:
        verdict = "SHIP"
    else:
        verdict = "REVIEW"

    return {
        "legs": (leg1, leg2, leg3), "count": count, "hil": hil,
        "irrev": irrev, "verdict": verdict, "findings": findings,
    }


def report(m, a):
    L = "①" if a["legs"][0] else "·"
    P = "②" if a["legs"][1] else "·"
    E = "③" if a["legs"][2] else "·"
    print("=" * 64)
    print(" AGENT TRIAGE  ·  %s" % m.get("agent", "<unnamed>"))
    print("=" * 64)
    print(" %s" % m.get("description", ""))
    print(" autonomous=%s  human_in_loop=%s  tools=%d"
          % (m.get("autonomous", True), a["hil"], len(m.get("tools", []))))
    print("-" * 64)
    print(" Trifecta legs:  %s untrusted  %s private  %s state/egress   (count=%d)"
          % (L, P, E, a["count"]))
    print("-" * 64)
    if a["findings"]:
        print(" FINDINGS")
        for sev, asi, msg in a["findings"]:
            print("  [%-4s] %s %s" % (sev, asi, OWASP.get(asi, "")))
            for line in _wrap(msg, 56):
                print("         %s" % line)
    else:
        print(" No findings.")
    print("-" * 64)
    note = {
        "GATE":  "Must NOT run autonomously. Break a leg or add human-in-the-loop.",
        "SHIP*": "Acceptable only because a human gates the risky step.",
        "SHIP":  "Bounded blast radius (≤ 2 legs, reversible).",
        "REVIEW":"Manual review needed.",
    }[a["verdict"]]
    print(" VERDICT: %-6s  %s" % (a["verdict"], note))
    print("=" * 64)


def _wrap(s, width):
    words, line, out = s.split(), "", []
    for w in words:
        if len(line) + len(w) + 1 > width:
            out.append(line); line = w
        else:
            line = (line + " " + w).strip()
    if line:
        out.append(line)
    return out


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "sample-agent.json"
    try:
        m = load(path)
    except FileNotFoundError:
        print("manifest not found: %s" % path); sys.exit(2)

    # light validation — catch typos in capability names
    for t in m.get("tools", []):
        bad = set(t.get("capabilities", [])) - VALID_CAPS
        if bad:
            print("WARN: tool '%s' has unknown capabilities: %s"
                  % (t.get("name"), ", ".join(sorted(bad))))

    a = assess(m)
    report(m, a)
    sys.exit(1 if a["verdict"] in ("GATE", "REVIEW") else 0)


if __name__ == "__main__":
    main()
