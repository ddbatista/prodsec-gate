# prodsec-gate

Agentic-security triage and gating tools. Vet an MCP server's advertised tools
for the **lethal trifecta** before it enters your agent catalogue, audit the
coding agent on your own machine, and threat-model a whole system with
**MAESTRO** in a shape where wrong answers are detectable.

- **Lethal trifecta:** an agent that combines ① untrusted input, ② access to
  private data and ③ the ability to change state or communicate externally can
  be steered by injected text into exfiltrating or destroying data. The
  **Rule of Two**: allow at most two of the three legs without a human gate —
  and gate any irreversible action regardless of leg count.
- **MAESTRO:** the Cloud Security Alliance's seven-layer threat-modelling
  framework for agentic AI. Here it is a constrained prompt plus a scorer that
  checks every finding's citation against the code.

## Install

```sh
pip install .                    # or: pip install -e .   (develop)
pipx install .                   # puts the commands on your PATH globally
pip install '.[live]'            # LLM classifier via Claude Code's credentials
pip install '.[live-api]'        # ...or via your own ANTHROPIC_API_KEY
```

**Zero dependencies**, deliberately. The offline core is Python-stdlib only:
every dependency is an ASI04 supply-chain surface in a tool whose job is to be
trusted about supply chain, *and* a reason the gate stops installing on someone
else's machine — and a security check that fails to install gets removed from
the pipeline, not fixed. The one path that needs a model lives behind the
`[live]` extra and is never on a required check.

## Commands

| Command | Does | Doc |
|---|---|---|
| `prodsec-fetch` | Capture a live MCP server's `tools/list` | [docs](docs/prodsec-fetch.md) |
| `prodsec-gate` | Vet that dump → verdict → exit code | [docs](docs/prodsec-gate.md) |
| `prodsec-triage` | Grade a hand-written agent manifest | [tooling](tooling/README.md) |
| `prodsec-adapter` | **Deprecated** alias of `prodsec-gate --json` (always exits 0 or 2) | [tooling](tooling/README.md) |
| `prodsec-audit` | Audit Claude Code / Codex / Cursor / your own agent | [tooling](tooling/README.md) |
| `prodsec-allowlist` | Grade a Claude Code allow-list by blast radius | [tooling](tooling/README.md) |
| `prodsec-maestro` | Print the MAESTRO pass prompt; score a pass's citations | [docs](docs/maestro-pass.md) |

## How to use

Every example below runs from a clone of this repo after `pip install .`.

### 1. Lethal trifecta: should this agent or MCP server ship?

The fast check, about a minute per agent.

**Vet a live MCP server.** `prodsec-fetch` captures its `tools/list` and
`prodsec-gate` grades it:

```sh
set -o pipefail                  # REQUIRED: otherwise a failed fetch looks like a pass

# Try it first against the bundled demo server (no third-party code):
prodsec-fetch --i-will-execute-this --stdio python3 examples/demo_mcp_server.py | prodsec-gate -

# Remote HTTP server (nothing executes locally):
prodsec-fetch --http https://example.com/mcp --header "Authorization: Bearer $TOK" | prodsec-gate -

# Local stdio server (this RUNS the server's code, so use a sandbox for unknown servers):
prodsec-fetch --i-will-execute-this --stdio npx -y @scope/server | prodsec-gate -
```

The demo server is built to fool the offline gate. One tool forwards customer
records but never uses an egress keyword, so it grades **SHIP when it should
GATE**. Add `--live` to have an LLM classify the descriptions as well; see
[docs/prodsec-gate.md](docs/prodsec-gate.md).

**Grade an MCP dump you already have.** If you commit dumps, name them
`<server>.tools.json` so the [pre-commit hook](docs/packaging-and-ci.md) picks
them up:

```sh
prodsec-gate tooling/mcp-dump.json            # → GATE (full trifecta), exit 1
prodsec-gate tooling/mcp-dump.json --json     # same verdict and exit code, as JSON with the manifest
```

**Grade a hand-written agent manifest.** The schema is in
[tooling/README.md](tooling/README.md):

```sh
prodsec-triage tooling/sample-agent.json            # → GATE: all three legs
prodsec-triage tooling/delete-db-agent.json         # → GATE: 2 legs, but irreversible
prodsec-triage tooling/delete-db-agent-fixed.json   # → SHIP: hardened version
```

**Audit your own coding agent's configuration:**

```sh
prodsec-audit --agent claude          # or codex, cursor, all
prodsec-allowlist                     # grade the Claude Code allow-list by blast radius
```

### 2. MAESTRO: do we understand this whole system?

The slow pass, an afternoon per system. Full guide in
[docs/maestro-pass.md](docs/maestro-pass.md).

```sh
# 1. Print the constrained prompt, set its scope, and give it to an agent
#    (a fresh session is best). In Claude Code, "run a MAESTRO pass on src/"
#    triggers the bundled skill instead.
prodsec-maestro --prompt

# 2. Save the agent's output as JSON (one object per finding, seven fields).

# 3. Score it. Every citation is checked against the code:
prodsec-maestro examples/maestro-pass-good.json --root .   # 2/2 CITED, exit 0
prodsec-maestro examples/maestro-pass-bad.json  --root .   # MISPLACED + FABRICATED + DROPPED, exit 1
```

The two example files show what a passing and a failing pass look like.
After scoring, **hand-check the CITED findings**. A real citation can still sit
under a wrong scenario, and the scorer cannot tell.

## Exit codes are the interface

| Code | Meaning |
|---|---|
| `0` | **SHIP** — ≤ 2 legs, nothing irreversible, *and something was actually audited* |
| `1` | **GATE** — full trifecta, or an irreversible action |
| `2` | **ERROR / NOT AUDITED** — a configuration failure, **not a pass** |

The `2` exists because `audit_allowlist.py` was once found exiting `0` when run
against a directory containing no config at all: "no rules found" and "rules
found and they are fine" were the same green light. **A gate that passes when it
did not run is worse than no gate, because something downstream believes it.**

**Always `set -o pipefail`.** A shell pipeline reports only the *last* command's
exit code, so an upstream fetch failure can be masked by a downstream success.

## What it does not do

- **`--live` defaults to the Agent SDK**, which is Claude Code as a library and
  therefore ships Bash, Read, Write and WebFetch. It is caged to zero tools and
  the cage is verified before each run — but that cage is load-bearing, and
  L17's union-never-subtract ratchet does **not** cover it: the ratchet bounds
  the verdict, not the host. `--backend api` has no tool surface to cage.
- **Offline, it misses egress phrased in vocabulary the patterns don't know.**
  A tool described as "forwards the selected customer record to our partner
  endpoint" grades `SHIP` at 2 legs. `--live` closes this; the offline default
  ships with the hole, on purpose and documented.
- **It reads declarations, not behaviour.** `tools/list` is what a server *says*
  it does, written by the server operator, who may be the attacker.
- **It cannot see intent.** A deliberately-vulnerable test fixture and a
  dangerous production server look identical to it.

## Verify it yourself

```sh
python3 -m unittest discover                          # stdlib only, no dev dependencies
python3 tooling/audit_agent_config.py --self-test     # 12/12
python3 tooling/audit_allowlist.py  --self-test       # 15/15, then 11/11
python3 tooling/policy_guard_hook.py --self-test      # 22/22
python3 tooling/maestro_score.py    --self-test       # 12/12

# end to end, with no third-party code (the demo is built to SHIP wrongly offline):
set -o pipefail
prodsec-fetch --i-will-execute-this --stdio python3 examples/demo_mcp_server.py | prodsec-gate -
```

## License

[MIT](LICENSE)
