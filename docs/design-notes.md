# Design notes

Why prodsec-gate is built the way it is, and what I found that made it so.

I built these tools across an agentic-security course (lessons L01–L18 and a
capstone), and most of the decisions below came from something going
wrong: a tool of mine passing when it should not have, or a control I trusted
turning out not to be one. The code keeps the *why* in plain words and links
here; this page keeps the story, the dates and the lesson each one came from.

Each heading has a stable anchor (`docs/design-notes.md#<id>`) that the code
points at. A test fails if a pointer names an anchor that is not on this page.

**Contents**

- *Verdicts and exit codes:*
  [Exit 2 means not audited](#exit-2-not-audited) ·
  [A verdict carries its instrument](#verdict-carries-instrument) ·
  [Empty input points upstream](#empty-input-points-upstream) ·
  [Show progress; fail fast](#visible-progress) ·
  [Run the documented commands](#run-the-docs)
- *The gate's pipeline:*
  [Offline by default](#offline-by-default) ·
  [Zero dependencies](#zero-dependencies) ·
  [Annotations are untrusted](#annotations-untrusted) ·
  [The keyword floor misses egress](#keyword-floor-misses-egress) ·
  [Union, never subtract](#union-never-subtract) ·
  [Fail closed](#fail-closed) ·
  [The description is data](#description-is-data) ·
  [Lock the Agent SDK down](#sdk-lockdown) ·
  [Fetching a stdio server runs it](#fetch-executes-code)
- *Auditing a coding agent:*
  [The two-property control test](#control-test) ·
  [Rules name tools; attackers want effects](#rules-name-tools-not-effects) ·
  [The hook is a one-way ratchet](#hook-one-way-ratchet) ·
  [Grade an allowlist by what can run](#allowlist-blast-radius) ·
  [The mode is the second axis](#mode-is-second-axis) ·
  [Match rules structurally, not by substring](#rule-matching-not-substring) ·
  [Path-shaped controls miss the environment](#environment-surface) ·
  [Auditing your own agent reads names, not behaviour](#harness-audit-reads-names)
- *Measuring the measurement:*
  [MAESTRO citations must be checkable](#maestro-citations-checkable) ·
  [Disclose the rigged target](#rigged-eval-disclosed)
- [Course map](#course-map)

---

## Verdicts and exit codes

<a id="exit-2-not-audited"></a>
### Exit 2 means not audited

**Decision.** Every command exits `0` (pass), `1` (finding) or `2` (not
audited), and every "could not look" path — missing or malformed input, nothing
to audit, a crash — ends in `2`. One helper (`tooling/_cli.py`) implements it,
and a test fails if a console script has no not-audited rows.

**What happened.** On 2026-09-20, while making the tools portable, I ran
`audit_allowlist.py` from `/tmp` and it printed "no rules found" and exited `0`.
"Did not find a config" and "found one and it is fine" were the same green
light, so a renamed settings file, a wrong `--project` or a CI runner without
the config would have passed forever. A gate that passes when it did not run is
worse than no gate, because something downstream believes it.

The same shape kept turning up:

- 2026-09-21: with no credential, every tool failed the classifier and the gate
  returned GATE — telling me the *server* was dangerous when my API key was
  missing. A finding about the subject and a failure of the instrument now have
  different exit codes (all tools failed closed → `2`; some → `1`).
- Before v0.2.0, which fixed them: `prodsec-triage` exited `1` (GATE) on a
  traceback and `0` (SHIP) on an empty manifest; `prodsec-gate --json` always
  exited `0`; the allowlist auditor treated a malformed settings file as absent
  and audited around it.

<a id="verdict-carries-instrument"></a>
### A verdict carries its instrument

**Decision.** Every verdict prints which instrument produced it and what that
instrument misses: the gate's INSTRUMENT block (keyword floor only, or floor
plus classifier; the floor's measured recall; how many tools failed closed; the
credential used), and the MAESTRO scorer's "CITED is not REAL" limit.

**What happened.** Fixing the allowlist's exit 0 (above) made me look one level
up: the offline gate printed `VERDICT: SHIP` with no statement that the
classifier never ran and that the keyword floor alone misses 37.5% of the
capabilities in my own corpus. A verdict without its denominator is
unattributable. I added the INSTRUMENT block on 2026-09-21 (capstone, day 2),
and the same day caught my own docs describing a behaviour the code never had:
they said `--live` falls back to the keyword floor when unavailable, when it
prints an error and exits `2`. Also on 2026-09-21, a `--live` run I assumed was using my
Claude Code login was in fact using an exported `ANTHROPIC_API_KEY`, announced
only by a stderr warning that scrolled past. The credential decides the bill,
the rate limit and whose org policy applies, so the gate now says which identity
it ran as.

<a id="empty-input-points-upstream"></a>
### Empty input points upstream

**Decision.** Empty input is reported as "no input — if you piped this, read the
upstream command's error; add `set -o pipefail`", never as a JSON parse error.

**What happened.** On 2026-09-21 `prodsec-fetch` hit a 403 and printed nothing,
and the gate downstream said `Expecting value: line 1 column 1` — sending me to
debug the wrong program. A shell pipeline reports only the last command's exit
code, so the upstream failure was invisible.

<a id="visible-progress"></a>
### Show progress; fail fast

**Decision.** With `--live`, the gate prints `[i/n] classifying <tool> …` to
stderr, and the Agent SDK backend sets a 60-second load timeout.

**What happened.** The Agent SDK backend spawns a Claude Code subprocess per
tool, about 3.5 s each, serially: three tools is 11 seconds of silence, a
40-tool server two minutes. On 2026-09-21 I reasonably assumed a run that had
not hung had hung. A gate that looks dead gets killed, and a killed gate teaches
people to stop running it. The same day I found that with an *invalid* key the
CLI does not fail fast: it ran past a 120-second timeout before its retries
finished. Very slow to fail is as bad as hanging for a gate — a check that takes
minutes to reject a bad credential is a check someone kills — but it is the one
a timeout can fix.

<a id="run-the-docs"></a>
### Run the documented commands

**Decision.** Install the package and run every command the docs show, as part
of shipping; the end-to-end demo and the installed console scripts are in CI.

**What happened.** On 2026-09-22 I installed the package and ran the documented
`prodsec-maestro --prompt`: it exited `2` with "the following arguments are
required: findings". It was the third time packaging or documenting had found a
defect that using the tool never did.

---

## The gate's pipeline

<a id="offline-by-default"></a>
### Offline by default

**Decision.** The required path (fetch → keyword floor → triage → exit code) is
stdlib-only, deterministic and free, so it is safe to block a build on. The LLM
classifier (`--live`) adds a network call, a credential, money and
non-determinism; it runs on a schedule and reports, and never blocks a merge.

**Why.** By the time I added a classifier (L17) the course had spent three
months establishing that an LLM in an enforcement path fails the first property
of the control test, and I had criticised two vendors for exactly that: Cursor's
Auto-review (L09), and — the seductive version, because it worked in my favour —
a model safety guardrail that refused 57 of 60 trials on 2026-09-20. A gate that
fails because someone's API quota ran out teaches people to bypass gates.

<a id="zero-dependencies"></a>
### Zero dependencies

**Decision.** The offline core is Python stdlib only; the model clients live
behind the `[live]` and `[live-api]` extras.

**Why.** Every dependency is a supply-chain surface (OWASP ASI04) in a tool
whose job is to be trusted about supply chain, and a reason the gate stops
installing on someone else's machine. A security check that fails to install
gets removed from the pipeline, not fixed. The test suite is stdlib `unittest`
for the same reason.

<a id="annotations-untrusted"></a>
### Annotations are untrusted

**Decision.** Capabilities are inferred from a tool's name, title and
description first; MCP annotations (`readOnlyHint`, `destructiveHint`, …) are
only a cross-check, and a contradiction between an annotation and the inferred
behaviour is flagged loudly and resolved toward the worse case.

**Why.** The MCP spec says clients must treat annotations as untrusted unless
they come from a trusted server — and the server is the party being vetted
(L04).

<a id="keyword-floor-misses-egress"></a>
### The keyword floor misses egress phrased in other words

**Decision.** The offline floor ships with this hole, on purpose and
documented: it reads keywords, and the server operator chooses the words.
`examples/demo_mcp_server.py` is built to exploit it, so the end-to-end demo
grades SHIP *wrongly*.

**What happened.** My own MAESTRO pass (L15, finding X3) found it. A tool called
`relay_to_partner` that "forwards the selected customer record to our partner
endpoint" gets no `external_comms`, because "relay", "forward" and "partner" are
in none of the patterns; the manifest reports two legs and triage prints SHIP. On
the 12-tool labelled corpus the floor's recall was 62.5%. That is what the
classifier signal is for — and why it had to be designed so it could not make
things worse. (In v0.3.0 I measured it on 20 real servers instead: 57.1%
before tuning the patterns against them, 65.3% after. `relay_to_partner` is
still missed: none of its words were worth adding.)

<a id="union-never-subtract"></a>
### Union, never subtract

**Decision.** `caps = keyword_caps | classifier_caps`. The classifier may add a
leg; it can never remove one. Where the two disagree is reported — that
disagreement is the output worth reading.

**Why.** This is the hook's one-way ratchet (L10, below) applied to a model. A
fully compromised classifier — one that has read an injected tool description
and is doing the attacker's bidding — can produce a false GATE. It cannot
produce a false SHIP. The failure mode is noise, not exposure. `eval_adapter.py`
states it as a measured property: an adversarial classifier that tries to
downgrade everything scores exactly the keyword baseline, never below it.

<a id="fail-closed"></a>
### Fail closed

**Decision.** A classifier that raised, timed out, refused, replied with junk or
replied with nothing has *not run*, and the tool is escalated, never treated as
"no extra legs". "Found nothing" must be said explicitly, as `none`. The policy
guard hook applies the same rule to itself: any crash denies.

**What happened.** The first version treated an *empty* reply as a clean run,
although its own comment said an empty reply is ambiguous with a refusal; the
property tests written for v0.2.0 caught it. For the hook, Claude Code's reference says
any exit code other than `0` or `2` is a non-blocking error and the tool call
proceeds — a crashing guard is an open guard — so every path in the hook is
wrapped and the `except` branch denies.

<a id="description-is-data"></a>
### The description is data

**Decision.** The classifier receives the tool text between `<tool>` tags with a
system prompt saying it is untrusted data written by the party being vetted, and
it may reply only with words from a four-word vocabulary. Anything else is
discarded.

**Why.** The thing reading attacker-authored text is itself an untrusted-input
surface. An injected description cannot make the classifier emit arbitrary text
into the manifest, because there is nowhere for arbitrary text to go. This is
the MAESTRO lesson (L15, day 2) aimed at my own detector: there, the control was
removing capability from the component that reads hostile text
(`repo_read=None`).

<a id="sdk-lockdown"></a>
### Lock the Agent SDK down

**Decision.** The default `--live` backend is the Claude Agent SDK, which uses
Claude Code's own credentials — and is Claude Code as a library, with Bash,
Read, Write and WebFetch built in. It runs with `tools=[]`, an explicit deny
list, `permission_mode="dontAsk"`, no setting sources and one turn, and the gate
verifies that lockdown before sending any attacker-authored text.

**Why.** Union-never-subtract bounds what a compromised classifier can do to the
*verdict*. It says nothing about what it can do to the *machine*: a classifier
that can be talked into running Bash is remote code execution with extra steps.
The ratchet protects the output channel; only capability removal protects the
host. The settings are belt and braces so a default changing underneath does not
silently re-arm the tools: deny rules beat allow in every mode (L11), and the
user's own settings are not loaded because that allow list was derived from
behaviour (L12). I kept this backend as the default deliberately; `--backend
api` has no tool surface to cage but needs its own key.

<a id="fetch-executes-code"></a>
### Fetching a stdio server runs it

**Decision.** `prodsec-fetch --stdio` refuses to start without
`--i-will-execute-this`, and the docs say to run it inside the Claude Code
sandbox (L13) with no write access and no egress beyond the server.

**Why.** To learn what a stdio server exposes you must run it — `npx -y
some-server` downloads and executes third-party code before you have decided to
trust it. The vetting step requires the subject to execute; that is the shape of
the problem, not a flaw in the plan. HTTP servers execute nothing locally but
may receive your token.

**What happened.** Two fixes on 2026-09-21:

- The 401 message used to promise "a pointer to its metadata" above a blank
  line. `api.anthropic.com` answers 401 with an *empty* `WWW-Authenticate`.
  When I asked whether any of the output was hardcoded, the answer was no — but
  the message described the spec (MCP authorization, L06) instead of the
  response. It now
  claims only what the server sent.
- Without a User-Agent, urllib sends `Python-urllib/3.x` and `mcp.sentry.dev`'s
  CDN returned Cloudflare error 1010 (a 403), which reads as the *server*
  refusing you when the request never reached it.

---

## Auditing a coding agent

<a id="control-test"></a>
### The two-property control test

**Decision.** The audits place every protection on a ladder (model → harness →
environment) and call something a *control* only if it passes two properties:

- **(a) not LLM-mediated** — injected text cannot argue past it; a classifier
  gate fails this by construction and is a *mitigation*;
- **(b) not writable by the party it constrains** — permission rules in a file
  the agent can edit fail this.

**Why.** It is the test the course gave me for "is this a control or a hope",
and it is why the gate keeps its LLM out of the required path
([offline by default](#offline-by-default)) and why the config audit's first
HIGH finding is the agent being able to edit its own settings.

<a id="rules-name-tools-not-effects"></a>
### Rules name tools; attackers want effects

**Decision.** `falsify_path_guard.py` attacks a path deny rule instead of
trusting it: it enumerates every surface that can change the bytes (file tools,
recognised shell commands, interpreters, containment) and reports each as
COVERED, UNCOVERED or UNKNOWN. UNKNOWN is not a pass.

**What happened.** In L08 I found that Claude Code's permission rules live in a
file the agent can write, and prescribed
`deny: Write(.claude/settings*.json), Edit(.claude/settings*.json)`. In L10 I
attacked my own fix. A deny rule names a *tool*; an attacker wants an *effect*.
Every uncovered surface is an equivalent-effect path — the same shape as the L07
day-2 bypass, where `notify_webhook` reached the transport that
`send_email_guarded` was protecting. Counting surfaces, the prescription covered
2 of 14.

On 2026-08-16 the permissions reference changed the model: only `Read(path)` and
`Edit(path)` rules are consulted for file access. A path rule on `Write` is
accepted and **never used** — my L08 prescription was an inert rule that reads
like a control — while one `Edit(path)` rule covers every built-in editor (the
script's docstring keeps the dated readings of the reference). On 2026-09-14 (L13) I added containment: the
interpreter rows are UNCOVERED by the rules' design, and only the sandbox, an OS
boundary rather than an enumeration, reaches them.

<a id="hook-one-way-ratchet"></a>
### The hook is a one-way ratchet

**Decision.** Instead of rule number fifteen, a PreToolUse hook stands where all
tool calls converge and denies effects on protected paths. It can only tighten:
a hook deny beats an allow rule, and a hook allow never clears a deny or ask
rule.

**What happened.** This was L10's second day: after counting 14 surfaces, the
answer was to stop naming tools. The hook matches Bash by the *spelling* of the
command — the allowlist-as-parser shape from L09, seen from the deny side — so
anything that both conceals a target and writes returns "ask", and reads like
`cat .claude/settings.json` are denied anyway. The self-test counts that
false-positive tax out loud. Later, the classifier's union-only rule borrowed
this ratchet.

<a id="allowlist-blast-radius"></a>
### Grade an allowlist by what can run

**Decision.** `audit_allowlist.py` grades allow rules by what they let execute,
not by how specific they look. `Bash(python3 -)` has no wildcard and permits
arbitrary code, because the program arrives on stdin.

**What happened.** An allow list built by clicking "don't ask again" is a policy
derived from behaviour (L12): nobody reviewed it. Writing the auditor, I made the
mistake it exists to catch, twice — the auditor's docstring records both, and
its test corpus keeps them. On L12's second day I added the read-only floor: Claude Code runs a
built-in set of read-only commands without a prompt in every mode (permissions
reference, 2026-08-25), so a rule that only restates the floor is noise — and
noise is what stopped anybody reading the list.

<a id="mode-is-second-axis"></a>
### The mode is the second axis

**Decision.** The config audit reports the permission mode alongside the rules,
and what the same rule set means in each mode.

**Why.** In L09 I took two axes from Codex: the sandbox is what the agent *can*
do, the approval policy is when it *asks*. Claude Code has the same pair, and I
had only audited one (L11). Rules say what is allowed; the mode decides what
happens to everything the rules did not decide. A rules-only audit reports on a
configuration that does not exist.

<a id="rule-matching-not-substring"></a>
### Match rules structurally, not by substring

**Decision.** The config audit parses a rule into tool and specifier and checks
whether that rule is *consulted* for the effect in question, and its self-test
pins every case it once got wrong.

**What happened.** My L15 MAESTRO pass (finding F8, 2026-09-17) found that a bare
substring test was deciding two HIGH/OK findings. `Write(.claude/settings*.json)`
matched, so the audit reported "the agent cannot rewrite its own constraints"
for a rule that is never consulted — while `falsify_path_guard.py`, in the same
directory, printed INERT for the same rule and exited `1`. Two tools, opposite
verdicts, and the reassuring one owned the exit code. I had recorded the inert
rule four weeks earlier; the fix had landed in prose and not in the function.
The same class would have counted `Read(./curl-notes.txt)` as an egress control.

<a id="environment-surface"></a>
### Path-shaped controls miss the environment

**Decision.** The config audit has an environment target: it lists credential
values and capability handles (such as `SSH_AUTH_SOCK`) that a subprocess would
inherit, and the sandbox `credentials.envVars` controls that reach them.

**Why.** Every control I had built was path-shaped: `Read(./.env)`,
`Edit(path)`, the hook's protected paths, the sandbox's `denyRead` (L14). A Read
deny on `~/.aws/credentials` says nothing about `AWS_SECRET_ACCESS_KEY` in the
environment, and protecting `~/.ssh` does not stop a process that inherits the
agent socket from making the agent *sign*. The same reasoning keeps the
`[live-api]` key in only the process that needs it.

<a id="harness-audit-reads-names"></a>
### Auditing your own agent reads names, not behaviour

**Decision.** `--agent harness` audits source, not config, with an AST and name
heuristic, and says so: every finding is a pointer to read a function, never a
verdict. The verdict comes from a red-team eval that ships a falsification case
— one that disables the control and must flip the result.

**What happened.** The heuristic is the same class of signal as the L03 keyword
baseline. Its first version scanned the whole AST including docstrings, so
`notify_webhook` — the L07 day-2 bypass — passed because its docstring
*mentioned* `ALLOWED_RECIPIENTS`. Prose is not enforcement. Separately (finding
X1), the check for a falsification case grepped for the word "falsif" rather than
running anything; my own red-team eval's falsify run did not actually flip its
verdict until 2026-09-17.

---

## Measuring the measurement

<a id="maestro-citations-checkable"></a>
### MAESTRO citations must be checkable

**Decision.** A MAESTRO pass must cite every finding as a file, a line and a
quote (the protocol came from L15; I built the scorer and the skill in L18), and
`prodsec-maestro` checks them mechanically into CITED, MISPLACED,
FABRICATED and DROPPED — then prints that CITED is not REAL.

**What happened.** The protocol is "constrain the output until being wrong is
detectable, then sample and score"; everyone does the first half because it is
one paste, nobody does the second because it is ten greps. The first time I ran
the scorer (2026-09-21, an L18 pass over `tooling/`), 9 of 10 line numbers were wrong and 10 of 10 quotes were
real, because the file had been edited an hour earlier: a checker that compared
line numbers would have reported 90% fabrication for a pass that invented
nothing. The quote is the anchor; the line is a hint. On 2026-09-23 I fixed
three real findings and re-scored the pass that raised them: their quoted lines
were gone, so the scorer called my remediated work FABRICATED. A finding marked
`fixed` is now checked the other way round, and judged by the line its fix
*added* — because one fix (finding F4 of my second pass) cleared a global at the
top of a function and left the cited line correctly in place. And a pass with all seven layers populated has generated rather than
observed — real systems have empty layers.

<a id="rigged-eval-disclosed"></a>
### Disclose the rigged target

**Decision.** `eval_adapter.py` runs offline by default against a hand-written
stub that recognises the phrasings the regex misses, and says loudly that it is
not a model and flatters the design by construction. `--live` is the real
measurement; `live_model.py` counts refusals as a third outcome, outside the
denominator, and deliberately disables server-side fallbacks.

**Why.** Every eval in the course ran against a rigged target from L05 on — the
lesson agent hardcoded its susceptibility so the lessons were deterministic and
free. That was right for teaching a control, and the L15 MAESTRO pass named the
cost: layer 1 (foundation models) was empty, so nothing had measured resistance,
only containment. L16's discipline is to report rates, not "it works better".
Counting a refusal as "contained" overstates the control — the very failure the
course exists to catch — and a fallback would silently swap the thing being
measured. The API facts behind this were verified 2026-09-17. On 2026-09-22 a
MAESTRO pass over the eval harness found that `complete()` cleared its
last-refusal record only on the refusal path, so in an N-trial loop a refusal at
trial 3 was still readable after trial 4 succeeded and was attributed to the
wrong trial; it now clears on entry. And until 2026-09-20 I was discarding a refusal's explanation:
when 57 of 60 live trials came back refused, the category alone ("cyber") could
not tell "it saw the injection" from "it objected to the data", so the adapter
now keeps the explanation.

---

<a id="course-map"></a>
## Course map

Reconstructed from the references the code carried before v0.2.0. Lessons not
referenced in the code are omitted.

| Lesson | What it built or found | Decisions above |
|---|---|---|
| L01, L03 | The triage verdict: legs, the Rule of Two, the irreversibility override; the keyword baseline | [harness audit](#harness-audit-reads-names) |
| L04 | The MCP adapter: inferring legs from `tools/list`; annotations untrusted; tool-list drift | [annotations](#annotations-untrusted) |
| L05 | The rigged eval target | [rigged target](#rigged-eval-disclosed) |
| L06 | MCP authorization (OAuth 2.1, RFC 9728) | [fetch](#fetch-executes-code) |
| L07 | Egress control; the day-2 `notify_webhook` bypass; "prompt text is not a control" | [effects](#rules-name-tools-not-effects), [harness audit](#harness-audit-reads-names) |
| L08 | The Claude Code config audit (2026-08-03); the self-modification hole | [effects](#rules-name-tools-not-effects) |
| L09 | Generalising the audit to Codex, Cursor and your own agent (2026-08-07); two axes; Cursor Auto-review | [mode](#mode-is-second-axis), [offline](#offline-by-default) |
| L10 | Falsifying the path guard (day 1); the PreToolUse hook (day 2) | [effects](#rules-name-tools-not-effects), [ratchet](#hook-one-way-ratchet) |
| L11 | Permission modes; deny beats allow in every mode | [mode](#mode-is-second-axis), [SDK lockdown](#sdk-lockdown) |
| L12 | The allowlist audit; the read-only floor (day 2) | [allowlist](#allowlist-blast-radius), [SDK lockdown](#sdk-lockdown) |
| L13 | The sandbox | [fetch](#fetch-executes-code), [effects](#rules-name-tools-not-effects) |
| L14 | The environment surface | [environment](#environment-surface) |
| L15 | The MAESTRO pass protocol; findings X1, X3, F4, F8; capability removal (day 2) | [citations](#maestro-citations-checkable), [floor](#keyword-floor-misses-egress), [substring](#rule-matching-not-substring), [data](#description-is-data), [rigged target](#rigged-eval-disclosed) |
| L16 | Report rates, not adjectives | [rigged target](#rigged-eval-disclosed) |
| L17 | The classifier signal | [offline](#offline-by-default), [union](#union-never-subtract), [fail closed](#fail-closed) |
| L18 | The MAESTRO pass skill and citation scorer | [citations](#maestro-citations-checkable) |
| Capstone | Day 1: packaging, `prodsec-fetch`, the gate, CI and the pre-commit hook. Day 2: the INSTRUMENT block | [instrument](#verdict-carries-instrument), [fetch](#fetch-executes-code), [run the docs](#run-the-docs) |
