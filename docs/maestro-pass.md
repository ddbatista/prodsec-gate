# prodsec-maestro — running a MAESTRO pass

Threat-model a system with MAESTRO's seven layers in a shape where wrong answers
are detectable, then **score the result by checking its citations**.

Source: [`tooling/maestro_score.py`](../tooling/maestro_score.py) ·
Skill: [`.claude/skills/maestro-pass/SKILL.md`](../.claude/skills/maestro-pass/SKILL.md) ·
Built in L18.

## The seven layers

| # | Layer |
|---|---|
| 1 | Foundation Models |
| 2 | Data Operations |
| 3 | Agent Frameworks |
| 4 | Deployment & Infrastructure |
| 5 | Evaluation & Observability |
| 6 | Security & Compliance (vertical — cuts across the others) |
| 7 | Agent Ecosystem |

Use the trifecta (`prodsec-triage`) to triage one agent in a minute; use
MAESTRO to sign off on a whole system over an afternoon.

## The thing to understand first

The protocol has two halves, and **only the second one is a control.**

Half one is a constrained prompt. You will do it reliably, because it is one
paste. Half two is *sample and score*, and it gets skipped, because it is ten
manual greps at the end of a long task — which makes it a control that works
right up until you are tired. This command is those ten greps.

It exists because requirement 1 of the prompt — `file.py:LINE`, quoted verbatim
— was chosen *because it is mechanically checkable*. Nothing else in a threat
model is.

## Usage

```sh
prodsec-maestro --prompt                            # print the pass prompt
prodsec-maestro --self-test                         # 12/12 bucket fixtures
prodsec-maestro PASS.json --root .                  # score a pass
cat PASS.json | prodsec-maestro - --root .          # or from stdin
```

| Exit | Meaning |
|---|---|
| `0` | every citation checks out |
| `1` | something was `FABRICATED`, `MISPLACED`, or `DROPPED` |
| `2` | nothing was scored — a configuration failure, **not a clean pass** |

## Run one, end to end

**1 — get the prompt.** It is stored in exactly one place. Never copy it into a
second file; a prompt that lives in two files gets updated in one.

```sh
prodsec-maestro --prompt
```

Replace `<PATHS>` with your scope (`src/`, `tooling/`, one module). Give it
to an agent — a subagent, a fresh session, or another model entirely.

**2 — save the findings as JSON**, never as prose. Prose cannot be scored.

```sh
mkdir -p tooling/maestro-passes
# agent writes -> tooling/maestro-passes/0003-my-pass.json
```

Each finding needs all seven fields. Missing any one and it is **dropped, not
fixed** — repairing it yourself re-introduces the unfalsifiable prose the shape
exists to exclude:

```json
{"layer": 3, "title": "short claim",
 "file": "src/server.py", "line": 73,
 "quote": "the line, verbatim",
 "scenario": "concrete input -> concrete wrong outcome",
 "falsifier": "what you would see if this were NOT real"}
```

`"layer": "cross"` for cross-layer findings; name both layers in the title.

**3 — score it.**

```sh
prodsec-maestro tooling/maestro-passes/0003-my-pass.json --root .
```

`--root` is the directory the `file` paths are relative to. Cite from the repo
root and run this from the repo root and it will line up.

**4 — hand-sample the `CITED` pile.** This is the step the tool cannot do for
you, and skipping it is the same mistake as skipping half two in the first
place. See *What it cannot decide* below.

## Reading the output

Three real lines, from three different runs during development (the cited
files belonged to the training workspace, not this repo) — no invented sample
output, for the same reason the prompt demands a verbatim quote:

```
 [ ok ]  1. L5  The eval prints an attack description that i        <- pass 0002
        harness/redteam_reviewer.py:53

 [MOVE]  1. L2  Description truncated to 200 chars before cl        <- pass 0001
        cited 88, actually at 100

 [FAB!]  1. L3  invented quote                                      <- a negative test
        line 10 exists but does not contain the quote; the quote appears nowhere in the file
```

| Bucket | Means |
|---|---|
| `CITED` | the line exists and says what was quoted |
| `MISPLACED` | the quote is real, the line number is not |
| `FABRICATED` | the file, the line, or the quoted text does not exist |
| `DROPPED` | a required field is missing — not a finding |
| `RESOLVED` | marked `"status": "fixed"`, and the evidence agrees |
| `UNFIXED` | marked fixed, and the evidence says otherwise |

**Read the `quotes that exist in the cited file` number first.** That is the
anti-hallucination measure, and it is not the same as the bucket counts:

```
  CITED        1 / 10
  MISPLACED    9 / 10
  FABRICATED   0 / 10
  DROPPED      0 / 10
--------------------------------------------------------------------
  quotes that exist in the cited file:  10 / 10
```

That is a real run (2026-09-21, the L18 pass over `tooling/`). One in ten looks
catastrophic; nothing was invented. Every line number was stale because the file
had been edited an hour earlier, and **an edit moves every line below it**. A
checker comparing only line numbers would have reported 90% fabrication and you
would have binned ten real findings.

> **The quote is the anchor; the line number is a hint.**

`MISPLACED` does not auto-repair, deliberately. The drift is information: it
tells you the file moved under the reviewer.

## Layer coverage

Every run prints which layers came back empty:

```
 LAYER COVERAGE
  EMPTY: L6 Security & Compliance
  Good. An empty layer is a finding you can point at.
```

All seven populated is **the tell** — real systems have empty cells, and a pass
with none has generated rather than observed. The prompt permits `EMPTY` and
requires it where true for exactly this reason. It caught the author of the
tool filling the grid on its first run.

## What it cannot decide

**`CITED` is not `REAL`.** The tool greps. It cannot know whether the failure
scenario would occur, so `MISCITED` — reasonable concern, real line, line does
not support the claim — sits *inside* the `CITED` pile. That is the dangerous
bucket, because it reads as real. The instrument block says so on every run
rather than leaving it in this file.

Worked example from a development pass that scored 8/8 `CITED`:
one finding claimed `REPO` being defined in two files meant the live eval kept
a stale binding. Sampling it took one command — `p.REPO is L.REPO` → `True`.
They alias the same dict; the risk is latent, not present. **The line supported
the concern and the scenario overstated it**, and only running it caught that.

Record sample verdicts back into the pass file so the next reader inherits them:

```json
{"…": "…", "sampled": "REAL",
 "sample_note": "Demonstrated 2026-09-22: self-minted token -> 200 'sent', approver never called."}
```

**Who may sample.** Running the mechanical score in the session that produced
the findings is fine — it is `grep`, not judgement. **Hand-sampling there is
not**: that is the author grading their own homework. Sample yourself, or in a
session that has not seen the reasoning. Where a finding can be *demonstrated*
by running code, do that instead of judging it, and paste the output into
`sample_note`.

**It cannot supply intent.** A deliberately-vulnerable fixture is not a
vulnerability. A test agent rigged on purpose is not a finding; a pass reporting its
trifecta as a finding has modelled the code and not the purpose.

## Recording fixes in the pass file

When you fix a finding, mark it and the pass re-verifies your remediation:

```json
{"…": "…", "status": "fixed",
 "fix_quote": "LAST_REFUSAL = None",
 "fix_note": "Fixed 2026-09-23: complete() clears it on entry."}
```

`status: "fixed"` inverts the check. Without a `fix_quote` the test is that the
**cited line is gone**; with one, the test is that the **fix_quote is present**.
Supply a `fix_quote` whenever the fix was an *addition* — otherwise the original
line legitimately survives and the finding is flagged `UNFIXED`. That flag is
the point: a pass file is a remediation record that re-checks itself, and
"we fixed that" stops being something you have to take on trust.

This mechanism exists because the first re-score after fixing three findings
reported them as `FABRICATED` — the scorer calling remediated work invented.

## Verify the scorer itself

```sh
prodsec-maestro --self-test          # 12/12
```

Twelve fixtures, one per bucket boundary: exact hit, indentation-insensitive
hit, stale line number, line past EOF, quote absent from the file, file absent,
missing required field, non-numeric line, and the four remediation cases —
fixed-by-deletion, fixed-by-addition, and both ways of failing to be fixed. They live in the module rather than
in a scratch directory, because a claim whose supporting run no longer exists
is not a verified claim — a pattern this repo has now caught itself in twice.

## Related

[`.claude/skills/maestro-pass/SKILL.md`](../.claude/skills/maestro-pass/SKILL.md) —
the same procedure as a Claude Code skill ·
[`prodsec-triage`](../tooling/README.md) — the fast per-agent heuristic this is
the slow whole-system counterpart to.
