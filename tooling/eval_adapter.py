#!/usr/bin/env python3
"""
eval_adapter.py — does the classifier signal actually improve the adapter?

Report RATES, not "it works better": per-leg recall and precision against a
hand-labelled corpus, baseline (keyword only) vs baseline + classifier signal.

Recall is the number that matters here. A missed leg is a tool that grades
SHIP when it should GATE (docs/design-notes.md#keyword-floor-misses-egress).
A false leg is noise: it costs a human a second look, which is the trade the
ratchet deliberately makes.

THE STAND-IN IS DISCLOSED, because the alternative is a rigged benchmark.
--rigged (the default) uses `semantic_stub`, a hand-written function that
recognises the phrasings the regex misses. It is NOT a model. It exists so the
eval runs offline, free and deterministically, and it flatters the classifier
by construction: it was written by someone who had already read the corpus.
Treat its numbers as an upper bound on the design, never as a measurement of a
model. --live is the real thing, and MAESTRO layer 1 stays EMPTY until you run it.
See docs/design-notes.md#rigged-eval-disclosed.
"""
import argparse
import glob
import hashlib
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
T = _load(os.path.join(HERE, "triage.py"), "triage")

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
                     if any(w in t for w in words)) or "none"


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


# ===========================================================================
# The real-server corpus (corpus/servers/*.json, schema in corpus/README.md).
#
# Ground truth is per tool: its capabilities and, for a state change, whether
# it can be undone. The server's expected verdict is a separate, human policy
# label. The derived verdict comes from running triage on what the detector
# inferred; the "oracle" verdict from running triage on the labels themselves.
# When derived and expected disagree, the oracle says whose problem it is:
#   detection  the oracle agrees with the label, so the legs were wrong
#   policy     the oracle disagrees too: right legs, disputed verdict
# A policy question is never fixed by weakening a pattern.

PERMISSIVE = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC",
              "0BSD", "Unlicense", "CC0-1.0"}
CAPTURE_METHODS = {"sandboxed-stdio", "remote-http"}
PROVENANCE = ("server", "package", "registry", "version", "source", "licence",
              "captured", "capture_method")
VERDICTS = {"SHIP", "GATE"}


def licence_ok(expr):
    """True when every licence an SPDX expression names is permissive. An OR
    is not taken as a choice: the corpus commits text under every licence it
    names, so all of them must allow that."""
    ids = str(expr or "").replace("(", " ").replace(")", " ").split()
    ids = [i for i in ids if i not in ("AND", "OR")]
    return bool(ids) and all(i in PERMISSIVE for i in ids)


def problems(fx):
    """Everything wrong with one server fixture; [] means valid."""
    out = []
    for field in PROVENANCE:
        if not str(fx.get(field) or "").strip():
            out.append("missing %s" % field)
    if fx.get("licence") and not licence_ok(fx["licence"]):
        out.append("licence %r is not on the permissive list" % fx["licence"])
    if fx.get("capture_method") and fx["capture_method"] not in CAPTURE_METHODS:
        out.append("capture_method %r is not one of %s"
                   % (fx["capture_method"], sorted(CAPTURE_METHODS)))
    if fx.get("expected_verdict") not in VERDICTS:
        out.append("expected_verdict must be SHIP or GATE")
    if not str(fx.get("rationale") or "").strip():
        out.append("missing rationale for the expected verdict")
    try:
        names = [t["name"] for t in A.tools_of(fx.get("tools"))]
    except (ValueError, KeyError, TypeError):
        return out + ["no captured tool list"]
    if not names:
        out.append("no captured tools")
    labels = fx.get("labels") or {}
    for n in sorted(set(names) - set(labels)):
        out.append("tool %s has no label" % n)
    for n in sorted(set(labels) - set(names)):
        out.append("label %s names a tool that was not captured" % n)
    for n, lab in sorted(labels.items()):
        caps = lab.get("capabilities")
        if not isinstance(caps, list) or set(caps) - set(A.CAP_VOCAB):
            out.append("%s: capabilities must be drawn from %s" % (n, ", ".join(A.CAP_VOCAB)))
            continue
        rev = lab.get("reversible")
        if "state_change" in caps and not isinstance(rev, bool):
            out.append("%s: a state_change label needs reversible true/false" % n)
        if "state_change" not in caps and rev is not None:
            out.append("%s: reversible is only for state_change tools" % n)
        if not str(lab.get("why") or "").strip():
            out.append("%s: missing why" % n)
    return out


def load_servers(directory):
    """Every *.json fixture in directory, validated. Raises ValueError listing
    every problem in every file, so a bad corpus is never scored."""
    paths = sorted(glob.glob(os.path.join(directory, "*.json")))
    if not paths:
        raise ValueError("no server fixtures in %s" % directory)
    servers, bad = [], []
    for p in paths:
        try:
            with open(p, encoding="utf-8") as f:
                fx = json.load(f)
        except (OSError, ValueError) as e:
            bad.append("%s: %s" % (os.path.basename(p), e))
            continue
        errs = problems(fx) if isinstance(fx, dict) else ["not a JSON object"]
        bad += ["%s: %s" % (os.path.basename(p), e) for e in errs]
        servers.append(fx)
    if bad:
        raise ValueError("invalid corpus:\n  " + "\n  ".join(bad))
    return servers


def fingerprint(servers):
    """What the recall baseline was measured on: every server's tools, labels
    and expected verdict. Provenance (capture date and so on) is left out, so
    a re-capture that changes nothing keeps the baseline."""
    body = [{"server": fx["server"], "tools": fx["tools"], "labels": fx["labels"],
             "expected_verdict": fx["expected_verdict"]}
            for fx in sorted(servers, key=lambda fx: fx["server"])]
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def _verdict(tools):
    m = {"human_in_loop": False,
         "tools": [{"name": n, "capabilities": sorted(caps),
                    "reversible": True if rev is None else rev}
                   for n, caps, rev in tools]}
    return T.assess(m)["verdict"]


def recall(c):
    return c["tp"] / (c["tp"] + c["fn"]) if c["tp"] + c["fn"] else 1.0


def precision(c):
    return c["tp"] / (c["tp"] + c["fp"]) if c["tp"] + c["fp"] else 1.0


def corpus_metrics(servers, infer=None):
    """Score a detector (default: the keyword floor) against the labels.

    infer(tool) -> (capabilities, reversible, notes), the shape of A.infer.
    """
    infer = infer or A.infer
    caps = {c: {"tp": 0, "fp": 0, "fn": 0} for c in A.CAP_VOCAB}
    misses, mismatches, disputes = [], [], []
    gated = acceptable = 0
    for fx in servers:
        derived, oracle = [], []
        for tool in A.tools_of(fx["tools"]):
            lab = fx["labels"][tool["name"]]
            truth = set(lab["capabilities"])
            got, rev, _ = infer(tool)
            got = {c for c in got if c in A.CAP_VOCAB}
            for c in A.CAP_VOCAB:
                if c in got and c in truth:
                    caps[c]["tp"] += 1
                elif c in got:
                    caps[c]["fp"] += 1
                elif c in truth:
                    caps[c]["fn"] += 1
            if truth - got:
                misses.append((fx["server"], tool["name"], sorted(truth - got)))
            derived.append((tool["name"], got, rev if "state_change" in got else None))
            oracle.append((tool["name"], truth, lab["reversible"]))
        d, o, want = _verdict(derived), _verdict(oracle), fx["expected_verdict"]
        if want == "SHIP":
            acceptable += 1
            gated += d == "GATE"
        if o != want:
            disputes.append(fx["server"])
        if d != want:
            mismatches.append({"server": fx["server"], "expected": want, "derived": d,
                               "oracle": o, "kind": "detection" if o == want else "policy"})
    overall = {k: sum(c[k] for c in caps.values()) for k in ("tp", "fp", "fn")}
    return {"capabilities": caps, "overall": overall, "misses": misses,
            "mismatches": mismatches, "policy_disputes": disputes,
            "gate_rate": {"gated": gated, "acceptable": acceptable},
            "servers": len(servers),
            "tools": sum(len(A.tools_of(fx["tools"])) for fx in servers)}


def _rate(k, n):
    if not n:
        return "%3d/%-3d =   n/a" % (k, n)
    lo, hi = wilson(k, n)
    return "%3d/%-3d = %5.1f%%  [%5.1f–%5.1f%%]" % (k, n, 100 * k / n if n else 0,
                                                   lo * 100, hi * 100)


def report_corpus(m):
    print("=" * 74)
    print(" REAL-SERVER CORPUS · %d servers · %d tools · keyword floor"
          % (m["servers"], m["tools"]))
    print("=" * 74)
    print("  %-16s %-34s %s" % ("leg", "recall", "precision"))
    for name, c in list(m["capabilities"].items()) + [("overall", m["overall"])]:
        print("  %-16s %-34s %s" % (name, _rate(c["tp"], c["tp"] + c["fn"]),
                                     _rate(c["tp"], c["tp"] + c["fp"])))
    print("\n  missed legs are missed GATEs; false legs cost a human a second look")
    g = m["gate_rate"]
    print("\n  GATE rate on acceptable servers  %s" % _rate(g["gated"], g["acceptable"]))
    print("    (servers labelled SHIP that the gate would block)")
    print()
    for x in m["mismatches"]:
        print("  MISMATCH %-9s %-28s expected %s, derived %s, labels give %s"
              % (x["kind"], x["server"], x["expected"], x["derived"], x["oracle"]))
    if not m["mismatches"]:
        print("  MISMATCH none: every derived verdict matches its label")
    hidden = [s for s in m["policy_disputes"]
              if s not in {x["server"] for x in m["mismatches"]}]
    for server in hidden:
        print("  POLICY   %-28s the labelled legs disagree with the expected verdict;"
              % server)
        print("           %-28s derived matches only because detection missed legs" % "")
    for server, tool, legs in m["misses"]:
        print("  MISS     %-28s %-24s %s" % (server, tool, ", ".join(legs)))
    print("=" * 74)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true")
    ap.add_argument("--corpus", default=os.path.join(HERE, "corpus.json"))
    ap.add_argument("--servers", metavar="DIR",
                    help="score the keyword floor on a real-server corpus "
                         "(corpus/servers) instead of the hand-written one")
    ap.add_argument("--write-baseline", metavar="FILE",
                    help="with --servers: record today's recall as the floor the "
                         "ratchet holds (review the diff: it must not go down)")
    a = ap.parse_args()
    if a.servers:
        try:
            servers = load_servers(a.servers)
        except ValueError as e:
            print("ERROR: %s" % e, file=sys.stderr)
            return 2
        m = corpus_metrics(servers)
        report_corpus(m)
        if a.write_baseline:
            legs = dict(m["capabilities"], overall=m["overall"])
            with open(a.write_baseline, "w") as f:
                json.dump({"servers": m["servers"], "tools": m["tools"],
                           "corpus_sha256": fingerprint(servers),
                           "floor_recall": {k: {"tp": c["tp"], "n": c["tp"] + c["fn"]}
                                            for k, c in legs.items()}},
                          f, indent=2)
                f.write("\n")
        return 0
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
