#!/usr/bin/env python3
"""
agent_sdk_backend.py — the L17 classifier signal, driven by the Claude Agent
SDK instead of the Anthropic API SDK.

WHY YOU MIGHT WANT THIS: it uses Claude Code's own credentials. No separate
ANTHROPIC_API_KEY to export, no second billing surface, and it works in exactly
the sessions where `live_model.py` kept failing with "Could not resolve
authentication method".

WHY IT NEEDS LOCKING DOWN, AND WHY THAT IS NOT OPTIONAL
-------------------------------------------------------
These are different products. The Anthropic SDK sends one message and returns
one message. The **Agent SDK is Claude Code as a library**: an agent loop plus
built-in Read, Write, Edit, Bash, Glob, Grep, WebSearch and WebFetch.

The component we are wiring it into reads `name` and `description` strings
written by the server operator -- the party we are vetting, i.e. the attacker in
the case that matters. Handing that component a Bash tool by default is L15 D2's
decision run backwards: there, the control was REMOVING capability from the
component that reads hostile text (`repo_read=None`).

**And the L17 ratchet does not save us here.** Union-never-subtract bounds what a
compromised classifier can do to the VERDICT -- worst case a false GATE, noise
rather than exposure. It says nothing about what a compromised classifier can do
to the MACHINE. A classifier that can be talked into running Bash is not a noisy
detector; it is remote code execution with extra steps. The ratchet protects the
output channel; only capability removal protects the host.

So the lockdown below is the control, and it is deliberately belt-and-braces --
four independent settings, any one of which would do, arranged so that a default
changing underneath us does not silently re-arm the tool surface:

    tools=[]                    nothing offered
    disallowed_tools=[...]      deny beats allow in every mode (L11/decision order)
    permission_mode="dontAsk"   anything unresolved is denied, never prompted
    setting_sources=[]          do not load the user's own settings, which may
                                carry allow rules we did not write (L12: that
                                allow list was derived from behaviour)
    max_turns=1                 no agent loop; one exchange
"""
import asyncio
import re

MODEL = "claude-opus-5"

# Named explicitly rather than relying on tools=[] alone. Deny rules apply in
# every permission mode, including bypassPermissions -- verified 2026-08-17.
DENY = ["Bash", "Read", "Write", "Edit", "NotebookEdit", "Glob", "Grep",
        "WebSearch", "WebFetch", "Task", "Agent"]


class NotConfigured(RuntimeError):
    pass


def _options(system, sink=None):
    from claude_agent_sdk import ClaudeAgentOptions
    return ClaudeAgentOptions(
        # The SDK launches the Claude Code CLI as a subprocess, and the CLI
        # writes startup notices to stderr -- one per call. With an API key
        # exported you get "claude.ai connectors are disabled ... takes
        # precedence" for every tool classified. It is not an error and it is
        # not about us: we asked for zero tools and zero connectors. But it
        # buries real output, so capture it and surface it only on failure.
        stderr=(sink.append if sink is not None else None),
        # Found 2026-09-21, and stated precisely because the difference matters:
        # with an INVALID key the CLI does not fail fast. It exceeded a 120s
        # timeout and was still running; it DID eventually return (the retries
        # finish), so this is "very slow to fail", not "hangs forever". Both are
        # bad for a gate -- a check that takes minutes to reject a bad
        # credential is a check someone kills -- but only the first is fixable
        # with a timeout, which is why one is set.
        load_timeout_ms=60000,
        system_prompt=system,
        tools=[],
        disallowed_tools=DENY,
        permission_mode="dontAsk",
        setting_sources=[],
        max_turns=1,
        model=MODEL,
        effort="low",
    )


async def _ask(system, payload, sink):
    from claude_agent_sdk import query, AssistantMessage, TextBlock
    out = []
    async for msg in query(prompt=payload, options=_options(system, sink)):
        if isinstance(msg, AssistantMessage):
            for b in msg.content:
                if isinstance(b, TextBlock):
                    out.append(b.text)
    return "".join(out)


def backend(system, payload):
    """Signature matches live_model's: (system, payload) -> text.

    Raises so that mcp_adapter.classify() records ok=False and the caller fails
    closed. Never returns an empty string quietly -- "found nothing" and
    "did not run" must stay distinguishable.
    """
    try:
        import claude_agent_sdk  # noqa: F401
    except ModuleNotFoundError:
        raise NotConfigured("claude-agent-sdk is not installed.\n"
                            "  pip install claude-agent-sdk")
    sink = []
    try:
        return asyncio.run(_ask(system, payload, sink))
    except Exception as e:
        # Only now is the captured CLI stderr interesting. Swallowing it
        # unconditionally would hide the diagnosis; printing it always buries
        # the report. Print it when, and only when, the call failed.
        noise = "\n".join(l.rstrip() for l in sink if l.strip())
        raise RuntimeError("%s: %s%s" % (type(e).__name__, e,
                                         ("\n  CLI stderr:\n  " + noise.replace("\n", "\n  "))
                                         if noise else ""))


def credential_source():
    """Which credential will actually be used, and why it matters.

    The SDK/CLI resolves in precedence order and the FIRST match wins:
        ANTHROPIC_API_KEY -> ANTHROPIC_AUTH_TOKEN -> claude.ai / ant profile
    Found 2026-09-21: a run that was assumed to be using the Claude Code login
    was in fact using an exported ANTHROPIC_API_KEY, announced only by a
    warning on stderr that scrolled past. The credential decides the bill, the
    rate limit, and WHOSE ORG POLICY APPLIES -- a gate should never be silent
    about which identity it ran as.
    """
    import os
    if os.environ.get("ANTHROPIC_API_KEY"):
        return ("ANTHROPIC_API_KEY",
                "an exported API key takes precedence over your claude.ai login; "
                "org connectors and policy from that login are NOT in effect")
    if os.environ.get("ANTHROPIC_AUTH_TOKEN"):
        return ("ANTHROPIC_AUTH_TOKEN", "an exported auth token takes precedence")
    return ("claude.ai / ant profile",
            "no key in this process, so the Claude Code login is used")


def self_check():
    """Prove the lockdown is real rather than asserted."""
    o = _options("x")
    checks = [
        ("tools offered", o.tools == [] or o.tools is None),
        ("tool denies present", set(DENY) <= set(o.disallowed_tools or [])),
        ("permission_mode dontAsk", o.permission_mode == "dontAsk"),
        ("setting_sources empty", o.setting_sources == []),
        ("single turn", o.max_turns == 1),
    ]
    for name, ok in checks:
        print("  %-24s %s" % (name, "PASS" if ok else "FAIL"))
    src, why = credential_source()
    print("  credential               %s" % src)
    print("      %s" % why)
    return all(ok for _, ok in checks)


if __name__ == "__main__":
    import sys
    print("Agent SDK backend — lockdown self-check")
    ok = self_check()
    if "--probe" in sys.argv:
        try:
            print("\nprobe reply:", repr(backend(
                "Reply with exactly the word: ok", "say ok")[:80]))
        except Exception as e:
            print("\nprobe failed: %s: %s" % (type(e).__name__, str(e)[:160]))
    sys.exit(0 if ok else 1)
