#!/usr/bin/env python3
"""
gate.py — the capstone. One command, one verdict, one exit code.

Seventeen lessons of artifacts, assembled into the thing that was the point:
a gate you can put in front of an MCP server before it enters your org's agent
catalogue. Everything it does was built and argued for elsewhere in this repo:

    tools/list dump          the untrusted input (L04)
      -> mcp_adapter.infer_signalled()
           keyword floor                                        (L04)
           + classifier signal, UNION ONLY, fail closed         (L17)
      -> triage verdict: legs, Rule of Two, irreversibility     (L01, L03)
      -> EXIT CODE                                              (the API)

EXIT CODES ARE THE INTERFACE. In CI nothing reads your prose:

    0  SHIP    <= 2 legs, nothing irreversible, everything audited
    1  GATE    full trifecta or an irreversible action -- do not run autonomously
    2  ERROR / NOT AUDITED -- a configuration failure, NOT a pass

The 2 is the one that matters and it is the lesson this file was written
around. On 2026-09-20 `audit_allowlist.py` was found exiting **0** when run
against a directory containing no config at all: "no rules found" and "rules
found and they are fine" produced the same green light. A gate that passes
when it did not run is worse than no gate, because something downstream
believes it. Every "nothing to audit" path here exits 2.

OFFLINE BY DEFAULT, ON PURPOSE. The whole path above is stdlib-only and
deterministic, so it is safe to block a build on. `--live` adds the classifier
and with it a network call, a credential, money and non-determinism -- none of
which belong in a required check. See the `[live]` extra in pyproject.toml.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import mcp_adapter as A          # noqa: E402
import triage as T               # noqa: E402

SHIP, GATE, ERROR = 0, 1, 2


# The keyword floor's measured recall on the 12-tool labelled corpus
# (tooling/corpus.json, eval_adapter.py). Printed, not merely documented --
# see the note in print_instrument().
FLOOR_RECALL = "62.5%"


def print_instrument(n_tools, live, backend_name, n_failed):
    """Always say which instrument produced this verdict, and what it misses.

    This is bug 1 of D1 applied to the gate's own headline path. `audit_allowlist`
    used to print "no rules found" and exit 0 -- "did not look" and "looked and it
    was fine" wearing the same face. The offline gate had the same shape one level
    up: it printed VERDICT: SHIP with no statement that the classifier never ran
    and that the floor alone misses 37.5% of the capabilities in our own corpus.
    A verdict without its denominator is unattributable.
    """
    print("-" * 64)
    print(" INSTRUMENT")
    if not live:
        print("  keyword floor only  ·  classifier NOT run  ·  --live adds it")
        print("  floor recall on the 12-tool corpus: %s" % FLOOR_RECALL)
        print("  so SHIP here means 'no keyword matched', NOT 'no capability'.")
    else:
        print("  keyword floor UNION classifier (%s)" % backend_name)
        print("  classified %d of %d tool(s); %d failed closed"
              % (n_tools - n_failed, n_tools, n_failed))
        try:
            import agent_sdk_backend as _asb
            src, _ = _asb.credential_source()
            print("  credential: %s" % src)
        except Exception:
            pass
    print("  reads DECLARATIONS (name/description), never behaviour.")


def build_manifest(dump, backend, server_name, progress=False):
    tools, failed_closed = [], []
    raw = _tools(dump)
    for i, t in enumerate(raw, 1):
        # The agent-sdk backend spawns a Claude Code CLI subprocess per tool,
        # ~3.5s each, serially. Three tools is 11 seconds of silence; a 40-tool
        # server is two minutes of it. Found 2026-09-21 when a run that had not
        # hung was reasonably assumed to have hung. A gate that looks dead gets
        # killed, and a killed gate teaches people to stop running it.
        if progress:
            print("  [%d/%d] classifying %s ..." % (i, len(raw), t.get("name", "?")),
                  file=sys.stderr, flush=True)
        caps, reversible, notes, ok = A.infer_signalled(t, backend)
        if not ok:
            failed_closed.append(t.get("name", "?"))
        tools.append({
            "name": t.get("name", "?"),
            "description": (t.get("description") or "")[:200],
            "capabilities": sorted(c for c in caps if c in T.VALID_CAPS),
            "reversible": True if reversible is None else reversible,
            "notes": notes,
        })
    return {"agent": server_name, "human_in_loop": False, "tools": tools}, failed_closed


def _tools(dump):
    if isinstance(dump, list):
        return dump
    for k in ("tools",):
        if k in dump:
            return dump[k]
    if "result" in dump and "tools" in dump["result"]:
        return dump["result"]["tools"]
    raise ValueError("could not find a tools list in input")


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="prodsec-gate",
        description="Vet an MCP server's tools/list before it enters your catalogue.")
    ap.add_argument("dump", help="tools/list JSON, or - for stdin")
    ap.add_argument("--name", help="label for the report; defaults to the input "
                                   "filename, or <stdin> when piped")
    ap.add_argument("--live", action="store_true",
                    help="add the LLM signal layer (network, credential, cost, "
                         "non-determinism) -- do NOT use in a required check")
    ap.add_argument("--backend", choices=["agent-sdk", "api"], default="agent-sdk",
                    help="DEFAULT agent-sdk: Claude Code as a library, uses ITS "
                         "credentials (no ANTHROPIC_API_KEY) -- locked to zero "
                         "tools, and the lockdown is verified before any "
                         "attacker-authored text is sent. api: Anthropic SDK, "
                         "one message and no tool surface at all, but needs its "
                         "own key. See docs/prodsec-gate.md for the trade.")
    ap.add_argument("--json", action="store_true", help="emit the manifest and exit")
    a = ap.parse_args(argv)

    try:
        raw = sys.stdin.read() if a.dump == "-" else open(a.dump).read()
    except OSError as e:
        print("ERROR: cannot read input: %s" % e, file=sys.stderr)
        return ERROR
    # Empty input almost always means the UPSTREAM command failed and the pipe
    # swallowed it. Reporting "not JSON" here sends you looking in the wrong
    # place -- observed 2026-09-21 when prodsec-fetch hit a 403 and this said
    # "Expecting value: line 1 column 1".
    if not raw.strip():
        print("ERROR: no input.\n"
              "       If you piped this, the upstream command produced nothing --\n"
              "       read ITS error, not this one. Shells return only the LAST\n"
              "       exit code in a pipeline, so add:  set -o pipefail",
              file=sys.stderr)
        return ERROR
    try:
        dump = json.loads(raw)
    except json.JSONDecodeError as e:
        print("ERROR: input is not JSON: %s" % e, file=sys.stderr)
        return ERROR

    backend = None
    if a.live:
        try:
            if a.backend == "agent-sdk":
                import agent_sdk_backend as asb
                print("  verifying Agent SDK lockdown before sending anything...",
                      file=sys.stderr)
                if not asb.self_check():
                    print("ERROR: Agent SDK lockdown self-check FAILED.\n"
                          "       This backend is Claude Code as a library: without the\n"
                          "       cage it carries Bash, Read, Write and WebFetch. The\n"
                          "       text about to be sent is written by the party being\n"
                          "       vetted. REFUSING.\n"
                          "       Use --backend api, which has no tool surface at all.",
                          file=sys.stderr)
                    return ERROR
                backend = asb.backend
            else:
                import live_model as lm             # tooling/, already on sys.path

                def backend(system, payload):        # noqa: F811
                    text, stop = lm.complete(system, payload, max_tokens=64,
                                             effort="low")
                    if stop.startswith("refusal"):
                        raise RuntimeError(stop)
                    return text
        except Exception as e:
            print("ERROR: --live requested but unavailable: %s: %s"
                  % (type(e).__name__, e), file=sys.stderr)
            return ERROR                              # fail closed, never silently offline

    try:
        manifest, failed_closed = build_manifest(
            dump, backend, a.name or ("<stdin>" if a.dump == "-"
                                      else os.path.basename(a.dump)),
            progress=bool(backend))
    except ValueError as e:
        print("ERROR: %s" % e, file=sys.stderr)
        return ERROR

    # NOTHING AUDITED is not a pass. See the module docstring.
    if not manifest["tools"]:
        print("ERROR: the dump contains no tools. Nothing was audited, so this\n"
              "       is a configuration failure, not a clean result.", file=sys.stderr)
        return ERROR

    if a.json:
        manifest["instrument"] = {
            "classifier": a.backend if backend else None,
            "floor_recall_on_corpus": FLOOR_RECALL,
            "failed_closed": failed_closed,
            "basis": "declarations",
        }
        print(json.dumps(manifest, indent=2))
        return SHIP

    # Reuse triage's own assessment -- one verdict function, not two.
    a_ = T.assess(manifest)
    T.report(manifest, a_)
    print_instrument(len(manifest["tools"]), bool(backend), a.backend,
                     len(failed_closed))

    if failed_closed:
        print("\n  FAIL-CLOSED on %d of %d tool(s): %s"
              % (len(failed_closed), len(manifest["tools"]), ", ".join(failed_closed)))
        # Found 2026-09-21 while writing the docs: with no credential EVERY tool
        # failed closed and this returned GATE -- telling the user the SERVER is
        # dangerous when the truth was that their API key was missing. A finding
        # about the subject and a failure of the instrument are different things
        # and must not share an exit code.
        if len(failed_closed) == len(manifest["tools"]):
            print("  EVERY tool failed closed, so the classifier never ran at all.")
            print("  That is a configuration failure (credential? network?), NOT a")
            print("  finding about this server. Fix it or drop --live; do not read")
            print("  this as a verdict.")
            return ERROR
        print("  The classifier did not run for these. A check that did not run")
        print("  is not a check that passed -- treating this as GATE.")
        return GATE

    return GATE if a_["verdict"] in ("GATE", "REVIEW") else SHIP


if __name__ == "__main__":
    sys.exit(main())
