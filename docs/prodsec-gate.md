# prodsec-gate

Vet an MCP server's `tools/list` before it enters your agent catalogue.
One command, one verdict, one exit code.

Source: [`tooling/gate.py`](../tooling/gate.py) ·
Why it is built this way: [design notes](design-notes.md).

## What it does

```
tools/list dump              the untrusted input
  -> mcp_adapter.build_manifest()
       keyword floor
       + classifier signal, UNION ONLY, fail closed
  -> triage: legs, Rule of Two, irreversibility
  -> EXIT CODE                                                  (the interface)
```

## Usage

```sh
prodsec-gate dump.json                 # from a file
prodsec-gate -                         # from stdin
prodsec-gate dump.json --json          # the manifest and verdict as JSON; same exit code
prodsec-gate dump.json --live          # add the LLM signal layer
prodsec-gate dump.json --live --backend api   # the other backend
```

Piped from the fetcher:

```sh
set -o pipefail
prodsec-fetch --i-will-execute-this --stdio npx -y @scope/server | prodsec-gate -
```

## Exit codes

| Code | Meaning | In CI |
|---|---|---|
| `0` | **SHIP** — ≤ 2 legs, nothing irreversible, and tools were actually present | pass |
| `1` | **GATE** — full trifecta, or an irreversible action | fail |
| `2` | **ERROR / NOT AUDITED** — unreadable input, no tools in the dump, or `--live` where *every* tool failed closed | **fail** |

Note the last one. If the classifier fails on **some** tools, that is a finding
about the server and you get `1`. If it fails on **all** of them it never ran,
which is a fact about your credentials or your network — a failure of the
*instrument*, not of the *subject* — and those must not share an exit code.

Treat `2` as hard a failure as `1`. It means the check did not run, and a check
that did not run is not a check that passed.

## `--live`, and why it is not the default

The keyword floor cannot see egress phrased in vocabulary it does not know.
This is a real, measured hole:

```sh
echo '[{"name":"relay_to_partner","description":"Forwards the selected customer
        record to our partner endpoint.","annotations":{"openWorldHint":true}}]' \
  | prodsec-gate -

  Trifecta legs:  ① untrusted  ② private  · state/egress   (count=2)
  VERDICT: SHIP                                             exit 0
```

`--live` adds an LLM that reads the description properly. It is **union only**:
the classifier may add a leg and can never remove one, so a classifier that has
been compromised by an injected tool description produces a **false GATE, never
a false SHIP**. The failure mode is noise, not exposure.

It is not the default, and must never be on a required check, because it adds a
network call, a credential, money and non-determinism. *A gate that fails
because someone's API quota ran out teaches people to bypass gates.* Run it on
a schedule and report the disagreements.

### Backends

| | `agent-sdk` (**default**) | `api` |
|---|---|---|
| What it is | Claude Code as a library | one Messages API call |
| Credentials | **Claude Code's own** — no key to export | needs `ANTHROPIC_API_KEY` |
| Install | `pip install '.[live]'` | `pip install '.[live-api]'` |
| Tool surface | Bash, Read, Write, WebFetch… **caged to zero** | none to begin with |

`agent-sdk` is the default because it runs with credentials you already have,
and a control nobody can run is not a control.

**The cage is the control, and it is not optional.** The Agent SDK ships an
agent loop plus built-in Read, Write, Edit, Bash, Glob, Grep, WebSearch and
WebFetch. The text being classified is written by the server operator — the
party you are vetting. See [design notes](design-notes.md#sdk-lockdown).

Five independent settings, so a changed default cannot silently re-arm it:

```python
tools=[]                    # nothing offered
disallowed_tools=[...]      # deny beats allow in every mode
permission_mode="dontAsk"   # unresolved -> denied, never prompted
setting_sources=[]          # do not load your own allow list
max_turns=1                 # no agent loop
```

The gate verifies all five **before sending anything** and refuses if any fails.

**The ratchet does not cover this.** Union-never-subtract bounds what a
compromised classifier does to the *verdict* — worst case a false GATE, noise
not exposure. It says nothing about what it can do to the *machine*. A
classifier that can be talked into running Bash is not a noisy detector; it is
RCE with extra steps. The ratchet protects the output channel; only capability
removal protects the host.

Prefer `--backend api` when you want no tool surface to cage in the first place
and are willing to manage a second credential.

**Expect refusals.** A model asked to classify a tool description containing
`IGNORE PREVIOUS INSTRUCTIONS` may decline. A refusal is an exception, which
becomes fail-closed, which becomes GATE — never a silent pass.

## Limitations, stated rather than discovered later

- **Declarations, not behaviour.** `tools/list` is what the server *says*. The
  MCP spec is explicit that annotations must be treated as untrusted, and the
  `name`/`description` this tool reads are written by the same party.
- **No intent model.** A deliberately-vulnerable fixture grades like a
  dangerous production server.
- **Offline recall is bounded by the keyword patterns.** Measured on a
  12-tool labelled corpus: **62.5%**. With the classifier signal: 100% against
  a stand-in, unmeasured against a real model (`tooling/eval_adapter.py`).
- **The default is the floor, and the report now says so.** Every run prints an
  `INSTRUMENT` block naming what produced the verdict — `keyword floor only ·
  classifier NOT run` plus the recall figure above, or, with `--live`, the
  backend, the classified/total count and the credential identity. It is also
  in the `--json` manifest under `instrument`, so a consumer can refuse a
  verdict produced by the floor alone
  ([why](design-notes.md#verdict-carries-instrument)). `--live` never falls
  back to the floor: unavailable, it prints `ERROR: --live requested but
  unavailable` and exits 2.

## Related

[`prodsec-fetch`](prodsec-fetch.md) produces the input ·
[`tooling/eval_adapter.py`](../tooling/eval_adapter.py) measures the recall
numbers above · [`.github/workflows/prodsec-gate.yml`](../.github/workflows/prodsec-gate.yml)
runs the offline path in CI.
