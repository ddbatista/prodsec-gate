---
name: maestro-pass
description: Threat-model a system with MAESTRO's seven layers in a shape where wrong answers are detectable, then score the result by checking its citations. Use when asked to threat-model a repo, agent, or MCP server; to sign off on a whole system rather than triage one agent; or to score findings a model has already produced.
---

# The MAESTRO pass

Two halves. The prompt is the cheap half and everyone does it. **The scoring is
the half that gets skipped, and it is the half that makes the output worth
anything.** Do not run the first without the second.

Reasoning and the layer table live in `docs/maestro-pass.md`.
Read it if you need the *why*; this file is the procedure.

## When this, and when not

| | trifecta / Rule of Two | MAESTRO |
|---|---|---|
| unit | one agent, one session | a whole system, over time |
| cost | a minute | an afternoon |
| use for | triage — deployable today? | sign-off — do we understand this? |

Triage with the trifecta (`prodsec-triage`). Sign off with this. CSA's own
position is that the trifecta is one condition MAESTRO flags, mostly in layers
1, 2 and 7 — so reaching for MAESTRO on a single agent is usually overkill.

## Step 1 — run the pass

`prodsec-maestro --prompt` prints the prompt. It is stored **once**, in
`tooling/maestro_score.py`, and nowhere else: a prompt that exists in two files
gets updated in one.

Two properties of that prompt are load-bearing, so do not "improve" them out:

- **It names the seven layers rather than saying "MAESTRO".** The framework name
  alone gets you a plausible seven-layer thing that may not be MAESTRO.
- **Every finding must carry a citation, a failure scenario, and a falsifier.**
  This is not thoroughness. It forces the output into a shape where being wrong
  is *detectable* — which is a different property from being right, and the only
  one you can verify. A finding missing any of the three is dropped, not fixed.

Output goes to a JSON file under `tooling/maestro-passes/`. Never straight to
prose: prose cannot be scored.

## Step 2 — score it

```sh
prodsec-maestro tooling/maestro-passes/NNNN-name.json --root .
# 0 every citation checks out · 1 fabricated/misplaced/dropped · 2 nothing scored
```

Buckets, and the boundary between them is the point:

- `FABRICATED` — the file, the line, or the quoted text does not exist.
- `MISPLACED` — the quote is real, the line number is not. Usually drift, not
  dishonesty: **any edit to the file moves every line below it.** Treat the
  quote as the anchor and the line number as a hint.
- `CITED` — the line exists and says what was quoted.

Read the **"quotes that exist in the cited file"** number first. That is the
anti-hallucination measure. Invented text does not appear in a file by accident;
a wrong line number appears by lunchtime.

## Step 3 — the part the tool cannot do

**`CITED` is not `REAL`.** The tool greps; it cannot know whether the failure
scenario would occur. `MISCITED` — reasonable concern, real line, line does not
support the claim — sits *inside* the CITED pile and is the dangerous bucket,
because it reads as real. Sample it by hand.

Running the mechanical score in the session that produced the findings is fine:
it is `grep`, not judgement. **Sampling the CITED pile in that session is not** —
that is the author grading their own homework. Sample it yourself, or in a fresh
session that has not seen the reasoning.

## Three tells that a pass was generated rather than observed

1. Findings true of any system — "vulnerable to data poisoning".
2. Mitigations with no threat attached — "consider defence in depth".
3. **All seven layers evenly populated.** Real systems have empty cells. The
   scorer prints layer coverage for exactly this reason, and it caught the
   author of this skill filling the grid on its first run.

## What no framework supplies

Intent. A deliberately-vulnerable fixture is not a vulnerability. If a pass
reports a rigged target's trifecta as a finding, it has modelled the code and
not the purpose.

## The transferable shape

This is not really about threat models. Any time an agent's output is prose and
the cost of a wrong answer is real: **constrain the output shape until being
wrong becomes detectable, then sample and score.** Code review, log triage,
reading a vendor's security claims.
