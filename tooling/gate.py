#!/usr/bin/env python3
"""
gate.py — one command, one verdict, one exit code.

A gate you can put in front of an MCP server before it enters your org's agent
catalogue:

    tools/list dump          the untrusted input
      -> mcp_adapter.build_manifest()
           keyword floor
           + optional classifier signal, UNION ONLY, fail closed
      -> triage verdict: legs, Rule of Two, irreversibility
      -> EXIT CODE                                              (the API)

EXIT CODES ARE THE INTERFACE. In CI nothing reads your prose:

    0  SHIP    <= 2 legs, nothing irreversible, everything audited
    1  GATE    full trifecta or an irreversible action -- do not run autonomously
    2  ERROR / NOT AUDITED -- a configuration failure, NOT a pass

The 2 is the one that matters: every "nothing to audit" path exits 2, never 0.
See docs/design-notes.md#exit-2-not-audited.

OFFLINE BY DEFAULT, ON PURPOSE. The whole path above is stdlib-only and
deterministic, so it is safe to block a build on. `--live` adds the classifier
and with it a network call, a credential, money and non-determinism -- none of
which belong in a required check. See docs/design-notes.md#offline-by-default.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import _cli                      # noqa: E402
import mcp_adapter as A          # noqa: E402
import triage as T               # noqa: E402

SHIP, GATE, ERROR = _cli.SHIP, _cli.GATE, _cli.ERROR


def print_instrument(n_tools, live, backend_name, n_failed):
    """Always say which instrument produced this verdict, and what it misses.

    SHIP from the keyword floor alone means "no keyword matched", not "no
    capability", and a verdict without its denominator is unattributable.
    See docs/design-notes.md#verdict-carries-instrument.
    """
    print("-" * 64)
    print(" INSTRUMENT")
    if not live:
        print("  keyword floor only  ·  classifier NOT run  ·  --live adds it")
        print("  floor recall on the 12-tool corpus: %s" % A.FLOOR_RECALL)
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


@_cli.entrypoint
def main(argv=None, backend=None):
    """backend: a classifier to use instead of building one from --live.
    In-process only (tests drive the live path with it); there is no flag."""
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
    ap.add_argument("--json", action="store_true",
                    help="emit the manifest and verdict as JSON; the exit code is "
                         "still the verdict's")
    a = ap.parse_args(argv)

    dump = _cli.read_json(a.dump)

    classifier = "injected" if backend else a.backend
    if backend is None and a.live:
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
        manifest = A.build_manifest(
            dump, backend, a.name or ("<stdin>" if a.dump == "-"
                                      else os.path.basename(a.dump)),
            classifier=classifier, progress=bool(backend))
    except ValueError as e:
        raise _cli.NotAudited(str(e))

    # NOTHING AUDITED is not a pass. See the module docstring.
    if not manifest["tools"]:
        raise _cli.NotAudited(
            "the dump contains no tools. Nothing was audited, so this\n"
            "       is a configuration failure, not a clean result.")

    # Reuse triage's own assessment -- one verdict function, not two.
    assessment = T.assess(manifest)
    failed_closed = manifest["instrument"]["failed_closed"]
    rc = verdict_code(assessment, failed_closed, len(manifest["tools"]))

    if a.json:
        # Machine-readable output must not turn the gate off: same verdict,
        # same exit code as the report.
        manifest["verdict"] = ("ERROR" if rc == ERROR else
                               "GATE" if failed_closed else assessment["verdict"])
        print(json.dumps(manifest, indent=2))
        if rc == ERROR:
            # stdout is a manifest; the failure must not live only inside it.
            print("ERROR: every tool failed closed, so the classifier never ran.\n"
                  "       This is a configuration failure, not a verdict.",
                  file=sys.stderr)
        return rc

    T.report(manifest, assessment)
    print_instrument(len(manifest["tools"]), bool(backend), classifier,
                     len(failed_closed))

    if failed_closed:
        print("\n  FAIL-CLOSED on %d of %d tool(s): %s"
              % (len(failed_closed), len(manifest["tools"]), ", ".join(failed_closed)))
        if rc == ERROR:
            print("  EVERY tool failed closed, so the classifier never ran at all.")
            print("  That is a configuration failure (credential? network?), NOT a")
            print("  finding about this server. Fix it or drop --live; do not read")
            print("  this as a verdict.")
        else:
            print("  The classifier did not run for these. A check that did not run")
            print("  is not a check that passed -- treating this as GATE.")
    return rc


def verdict_code(assessment, failed_closed, n_tools):
    """The exit code for a triage assessment plus the classifier's non-runs."""
    if failed_closed:
        # A finding about the subject and a failure of the instrument must not
        # share an exit code: if EVERY tool failed closed the classifier never
        # ran (a missing credential, say), which is not a verdict on the server.
        # See docs/design-notes.md#exit-2-not-audited.
        return ERROR if len(failed_closed) == n_tools else GATE
    return GATE if assessment["verdict"] in ("GATE", "REVIEW") else SHIP


if __name__ == "__main__":
    sys.exit(main())
