#!/usr/bin/env python3
"""
eval_adapter.py — does the classifier signal actually improve the adapter?

L16's discipline applied to a detector: report RATES, not "it works better".
Per-leg recall and precision against a hand-labelled corpus, baseline
(keyword only) vs baseline + classifier signal.

Recall is the number that matters here. A missed leg is a tool that grades
SHIP when it should GATE -- the X3 failure. A false leg is noise: it costs a
human a second look, which is the trade the ratchet deliberately makes.

THE STAND-IN IS DISCLOSED, because the alternative is a rigged benchmark.
--rigged (the default) uses `semantic_stub`, a hand-written function that
recognises the phrasings the regex misses. It is NOT a model. It exists so the
eval runs offline, free and deterministically, and it flatters the classifier
by construction: it was written by someone who had already read the corpus.
Treat its numbers as an upper bound on the design, never as a measurement of a
model. --live is the real thing, and MAESTRO layer 1 stays EMPTY until you run it.
"""
import argparse
import importlib.util
import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


A = _load(os.path.join(HERE, "mcp_adapter.py"), "mcp_adapter")

SEMANTIC = {
    "external_comms": ("forward", "relay", "partner", "endpoint", "third-party",
                       "outside", "vendor", "upload", "replicate", "mirror",
                       "channel", "hands the", "external"),
    "private_data":   ("customer", "case file", "ledger", "internal", "record",
                       "pii", "bucket"),
    "state_change":   ("applies", "adjustment", "reconcile", "delete", "undone"),
    "untrusted_input": ("fetch", "url", "email", "diagnostics"),
}


def semantic_stub(system, payload):
    """A HAND-WRITTEN stand-in for a model. Not a model. See the docstring."""
    t = payload.lower()
    return "\n".join(cap for cap, words in SEMANTIC.items()
                     if any(w in t for w in words))


def live_backend(system, payload):
    sys.path.insert(0, HERE)
    import live_model as lm
    text, stop = lm.complete(system, payload, max_tokens=64, effort="low")
    if stop.startswith("refusal"):
        raise RuntimeError("refusal:%s" % stop)
    return text


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p, d = k / n, 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (max(0.0, (c - m) / d), min(1.0, (c + m) / d))


def score(corpus, backend):
    tp = fp = fn = 0
    failed_closed = 0
    misses = []
    for row in corpus:
        truth = set(row["legs"])
        if backend is None:
            got, _, _ = A.infer(row["tool"])
            ok = True
        else:
            got, _, _, ok = A.infer_signalled(row["tool"], backend)
        if not ok:
            failed_closed += 1
        # openWorldHint fabricates untrusted_input; judge only the legs we label
        got = {c for c in got if c in A.CAP_VOCAB}
        tp += len(truth & got)
        fp += len(got - truth)
        missing = truth - got
        fn += len(missing)
        if missing:
            misses.append((row["tool"]["name"], sorted(missing)))
    return tp, fp, fn, failed_closed, misses


def report(label, corpus, backend):
    tp, fp, fn, fc, misses = score(corpus, backend)
    rec, prec = tp / (tp + fn) if tp + fn else 0, tp / (tp + fp) if tp + fp else 0
    lo, hi = wilson(tp, tp + fn)
    print("\n  %s" % label)
    print("    recall    %2d/%-2d = %5.1f%%  [%4.1f–%4.1f%%]   <- missed legs are missed GATEs"
          % (tp, tp + fn, rec * 100, lo * 100, hi * 100))
    print("    precision %2d/%-2d = %5.1f%%              <- false legs are noise, not exposure"
          % (tp, tp + fp, prec * 100))
    if fc:
        print("    failed closed on %d tool(s) — escalate, do not pass" % fc)
    for name, legs in misses:
        print("    MISS  %-20s %s" % (name, ", ".join(legs)))
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true")
    ap.add_argument("--corpus", default=os.path.join(HERE, "corpus.json"))
    a = ap.parse_args()
    corpus = json.load(open(a.corpus))

    print("=" * 74)
    print(" ADAPTER SIGNAL EVAL · %d labelled tools · %s"
          % (len(corpus), "LIVE" if a.live else "STUB (not a model — see docstring)"))
    print("=" * 74)

    base = report("baseline · keyword patterns only", corpus, None)
    backend = live_backend if a.live else semantic_stub
    sig = report("baseline + classifier signal (union only)", corpus, backend)

    print("\n" + "-" * 74)
    print("  recall %5.1f%% -> %5.1f%%" % (base * 100, sig * 100))
    print("\n  The ratchet, stated as a property rather than a hope:")
    evil = lambda s, p: "untrusted_input"          # noqa: E731
    worse = report("  adversarial classifier (tries to downgrade everything)",
                   corpus, evil)
    print("\n  A classifier doing the attacker's bidding scored %5.1f%% recall —"
          % (worse * 100))
    print("  never BELOW the %5.1f%% baseline, because union cannot subtract." % (base * 100))
    print("=" * 74)
    return 0 if sig >= base else 1


if __name__ == "__main__":
    sys.exit(main())
