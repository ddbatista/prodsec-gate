# Changelog

## v0.3.0

Detection is now measured on real MCP servers, and the keyword floor is tuned
against them. **Verdicts can change:** the keyword patterns are different, so
some tools gain or lose legs. Read the table before upgrading a required
check.

### The keyword floor on the real-server corpus

20 public MCP servers, 222 tools, labelled by hand (`corpus/`). v0.2.0 was
measured on the same corpus with its own patterns.

| | v0.2.0 | v0.3.0 |
|---|---|---|
| Recall, all legs | 173/303 (57.1%) | 198/303 (65.3%) |
| 95% interval (resampling servers) | 46.3–67.9% | 54.3–75.5% |
| `untrusted_input` recall | 84/99 | 92/99 |
| `private_data` recall | 29/74 | 37/74 |
| `external_comms` recall | 18/48 | 25/48 |
| `state_change` recall | 42/82 | 44/82 |
| Precision, all legs | 173/318 (54.4%) | 198/342 (57.9%) |
| Servers labelled GATE that are gated | 12/12 | 12/12 |
| Servers labelled SHIP that are blocked | 2/8 (fetch, tavily) | 1/8 (fetch) |

Precision rises on every leg, as does recall. The patterns were tuned on this
same corpus, so treat v0.3.0's figures as an upper bound;
`tests/test_patterns.py` pins descriptions from server kinds the corpus lacks.
On the 12-tool hand-written corpus nothing changed (62.5% recall, 47.6%
precision).

### Behaviour changes

- **Keyword patterns** (`mcp_adapter.SIGNALS`), so some legs change:
  - **New words:**
    - `untrusted_input`: `contents`, `commit` or `commits`, `research`
    - `state_change`: `push`
    - `external_comms`: a publishing phrase (create, add, post or reply
      followed by an issue, comment, review, or pull or merge request)
  - **New plurals:**
    - `untrusted_input`: `messages`, `reviews`, `issues`
    - `private_data`: `files`, `repositories`
    - `external_comms` still matches only `message`.
  - **Narrowed `http`:** it no longer fires before "header".
  - **Narrowed `knowledge`:** only a knowledge base or graph counts.
  - **Negations:** words a description negates are dropped before any
    check. "Does not run or modify the monitor" no longer counts toward a
    leg, the irreversibility check, or the `readOnlyHint` contradiction
    check.
- **The `INSTRUMENT` block and the `--json` manifest** report floor recall
  measured on the real corpus.
  - **INSTRUMENT line:** v0.2.0 printed `floor recall on the 12-tool corpus:
    62.5%`. It now prints `floor recall on the real-server corpus (20 servers,
    222 tools): 65.3%`. Update anything that parses it.
  - **`--json` manifest:** `instrument.floor_recall_on_corpus` is now
    `"65.3%"`, and a new field, `instrument.floor_corpus`, holds `"20
    servers, 222 tools"`.
- **`prodsec-fetch`**
  - **Waits for each answer before sending the next request.** The Python
    MCP SDK shuts down on EOF and drops the request in flight. Before this,
    the reference Python servers (time, fetch, git) returned no tools.
  - **Follows `tools/list` pagination** (`nextCursor`). It used to return only
    the first page.
  - **New error messages:** they name the step that failed and include the
    tail of the server's stderr, for example `server exited before answering
    initialize`. The old `no tools/list response` message is gone. A
    JSON-RPC error reply now fails with `server answered tools/list with an
    error: …`.
- **Unchanged:** a tool that declares no `openWorldHint` still counts as
  untrusted input. Treating it as unknown cut `untrusted_input` recall from
  92/99 to 72/99, so it did not ship (#13).

### Other changes

- **`corpus/`:** the real-server corpus, with its schema and labelling rules,
  a capture script that runs each server under a macOS `sandbox-exec` profile,
  and a fingerprinted recall baseline.
- **`eval_adapter.py --servers corpus/servers`** exits 0 on any result (the
  ratchet lives in the tests) and 2 on an invalid corpus.
  - `--write-baseline FILE` records the floor and the corpus fingerprint.
    Without `--servers` it exits 2.
  - The report lists every missed leg (`MISS`) and every policy dispute a
    detection miss hides (`POLICY`). It also reports:
    - per-leg recall and precision, with intervals that resample servers
    - per-server averages
    - GATE recall on servers labelled GATE, and the GATE rate on servers
      labelled SHIP
    - every mismatch, classified as detection, policy or both
- **The recall ratchet** (`tests/test_corpus.py`) fails if any leg's recall,
  or the share of servers labelled GATE that are gated, drops below the
  committed baseline.
- **`examples/maestro-pass-bad.json`** shows MISPLACED again, as the README
  says. Its quote had drifted and it reported FABRICATED instead.

## v0.2.0

One exit-code contract for every command, a test suite, and command-surface
fixes. **No keyword or verdict changes:** the keyword patterns and the
triage rules are untouched, and the adapter eval's output is byte-identical to
v0.1.1. The `--live` reply parser did change; see the last item under
[Behaviour changes](#behaviour-changes-1).

### The contract

| Code | Meaning |
|---|---|
| `0` | SHIP (pass) |
| `1` | GATE (finding) |
| `2` | not audited: bad input, nothing to audit, or a crash |

Every console script follows it. An uncaught exception, or a command that
returns no verdict, now exits `2`. Before, a crash exited `1`, which reads as
GATE, and a missing verdict exited `0`, which reads as SHIP.

### Behaviour changes

If a script or CI job checks these exit codes, read this list before
upgrading.

- **`prodsec-triage`**
  - **Requires its manifest argument.** It used to fall back to
    `sample-agent.json`. Pass `-` to read stdin.
  - **Exits `2` on input it can't audit:** empty stdin, malformed JSON, a
    manifest with no tools, or a crash. Before, these exited `1` (with a
    traceback), or `0` when an empty manifest SHIPped. A missing file already
    exited `2`.
- **`prodsec-gate`**
  - Input that used to crash it now exits `2`.
  - **`--json` exits with the verdict's code.** It always exited `0` before.
    The JSON now carries `verdict` and `instrument`.
  - When every tool fails closed under `--live`, `--json` also prints an
    `ERROR:` line on stderr.
- **`prodsec-adapter` is deprecated.** It is now an alias of
  `prodsec-gate --json` and prints a warning on stderr.
  - It exits `0` when it produces a manifest, even one that would GATE, and
    `2` otherwise. It never exits `1`.
  - Its output is now the gate's manifest. The old `description`,
    `autonomous` and `INFER:` lines are gone. In the manifest itself:
    - `agent` is the input's file name (or `--name`), not the dump's
      `agent` field or `mcp-server`.
    - Every tool carries a `reversible` field. It used to be left out when
      nothing pointed either way.
    - Each tool's `description` is cut to 200 characters.
  - It passes every argument through to the gate, so `--live` and `--name`
    work too.
  - Use `prodsec-gate --json` instead.
- **`prodsec-allowlist`**
  - A settings file that exists but is malformed now exits `2` and names the
    file. Before, it was silently treated as absent.
  - A `--project` that doesn't exist exits `2`.
- **`prodsec-audit`**
  - A config file that exists but can't be read exits `2` after the report.
    That includes a Codex `config.toml` on Python < 3.11.
  - A `--project` that doesn't exist exits `2`.
- **`prodsec-maestro`:** input that used to crash it now exits `2`.
- **`prodsec-fetch`:** a crash now exits `2`. It used to exit `1`.
- **Pre-commit hook**
  - It matches `*.tools.json` and `*dump*.json`.
  - **It no longer matches `.mcp.json`.** That file is a server config, not
    a `tools/list` dump, so grading it failed every commit that touched it.
  - Name committed dumps `<server>.tools.json`.
- **`--live` classifier reply parsing**
  - When nothing applies, the model must now say so with `none`. An empty
    reply fails closed. It used to count as a clean result.
  - A trailing `.` or `!` is now ignored on every line. So a reply of
    `private_data.` counts as that leg. In v0.1.1 it matched nothing and the
    tool failed closed.

### Other changes

- A stdlib `unittest` suite in `tests/`. Run it with
  `python -m unittest discover`. CI runs it on Python 3.9 to 3.13.
- The design rationale moved out of code comments into
  [`docs/design-notes.md`](docs/design-notes.md).

## v0.1.1

- CI asserts that the deliberately vulnerable fixture GATEs, instead of
  gating it as if it were a real dump. No functional changes to the tools.

## v0.1.0

- First release.
