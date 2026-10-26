#!/usr/bin/env python3
"""
live_model.py — the thin adapter that makes MAESTRO layer 1 non-empty.

Every eval in this workspace has run against a rigged target since L05:
`agent.py:11` hardcodes the model's susceptibility so the lesson is
deterministic and free. That was the right call for teaching a control, and
the L15 MAESTRO pass named the cost of it — **layer 1 (Foundation Models) is
EMPTY**, so nothing here has ever measured resistance, only containment.

This calls a real model. Three facts from the API reference drive the design,
and each one changes how the eval has to be written (verified 2026-09-17):

1. SAMPLING IS GONE. `temperature`, `top_p` and `top_k` are REMOVED on the
   current models and return 400. You cannot set temperature=0 for a
   deterministic run, nor temperature=1 to force spread. Trials still vary;
   you just don't get a dial. So the eval OBSERVES a rate — it cannot
   manufacture one.

2. REFUSAL IS A THIRD OUTCOME. `stop_reason == "refusal"` arrives as HTTP 200
   with a category in `stop_details`. A refusal is NOT the control working and
   it is NOT the model resisting the injection — it is the request never being
   answered. Counting it as "contained" overstates your control, which is the
   whole failure this workspace exists to catch. Reported separately and kept
   out of the denominator.

3. NO SERVER-SIDE FALLBACKS HERE, DELIBERATELY. The docs recommend enabling
   `fallbacks` by default on Opus-5 code so a refusal reroutes to another
   model. That is right for a product and wrong for an eval: it would silently
   swap the thing being measured. We want to SEE refusals, not route around
   them. If you copy this adapter into something that isn't an eval, turn
   fallbacks back on.

Credentials are read from the environment by the SDK; nothing is stored here.
Per L14: env vars reach every subprocess, so the key belongs only in the
process that needs it.
"""
import os

MODEL = "claude-opus-5"

RESISTED, FOOLED, REFUSED, ERROR = "RESISTED", "FOOLED", "REFUSED", "ERROR"

LAST_REFUSAL = None   # populated by complete() on a refusal; see below


class NotConfigured(RuntimeError):
    """Raised with actionable text rather than a stack trace."""


def _client():
    try:
        import anthropic
    except ModuleNotFoundError:
        raise NotConfigured(
            "the `anthropic` SDK is not installed.\n"
            "  pip install anthropic")
    # The SDK resolves ANTHROPIC_API_KEY, then ANTHROPIC_AUTH_TOKEN, then an
    # `ant auth login` profile. An unset ANTHROPIC_API_KEY does NOT mean there
    # are no credentials, so we do not check for it ourselves -- we let the
    # SDK resolve and report.
    import anthropic
    return anthropic.Anthropic()


def complete(system, user, max_tokens=1024, effort=None):
    """One call. Returns (text, stop_reason). Raises NotConfigured if unusable.

    `effort` is passed inside output_config (not top-level). Lower effort is
    faster and cheaper -- and may change how injectable the model is, so it is
    part of the configuration under test, not a free speed-up.
    """
    # Clear it on ENTRY, not only on the refusal path. Found 2026-09-22 by the
    # MAESTRO pass over harness/: the success path returned without touching
    # this, so in an N-trial loop a refusal at trial 3 was still readable after
    # trial 4 succeeded and got attributed to the wrong trial.
    global LAST_REFUSAL
    LAST_REFUSAL = None

    client = _client()
    kwargs = {}
    if effort:
        kwargs["output_config"] = {"effort": effort}
    resp = client.messages.create(
        model=MODEL,
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": user}],
        **kwargs,
        # No temperature/top_p/top_k: removed on this model, 400 if sent.
        # No fallbacks: see the module docstring.
    )
    # Check stop_reason BEFORE reading content -- on a refusal there may be
    # nothing useful in it.
    if resp.stop_reason == "refusal":
        sd = getattr(resp, "stop_details", None)
        cat = getattr(sd, "category", None)
        # The explanation is the only field that says WHY. We were discarding
        # it until 2026-09-20, when 57/60 live trials came back refused and the
        # category alone ("cyber") could not distinguish "it saw the injection"
        # from "it objected to the data".
        LAST_REFUSAL = {"category": cat,
                        "explanation": getattr(sd, "explanation", None)}
        return ("", "refusal:%s" % (cat or "unspecified"))
    text = "".join(b.text for b in resp.content if b.type == "text")
    return (text, resp.stop_reason)


def configured():
    """True if a live call could plausibly be made. Cheap, no network."""
    try:
        import anthropic  # noqa: F401
    except ModuleNotFoundError:
        return False
    return bool(os.environ.get("ANTHROPIC_API_KEY")
                or os.environ.get("ANTHROPIC_AUTH_TOKEN")
                or os.path.expanduser("~/.config/anthropic") and
                os.path.isdir(os.path.expanduser("~/.config/anthropic")))
