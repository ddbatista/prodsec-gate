# Changelog

## v0.2.0

One exit-code contract for every command, a test suite, and command-surface
fixes. **No detection changes:** the keyword patterns are untouched, and the
adapter eval's output is byte-identical to v0.1.1.

### The contract

| Code | Meaning |
|---|---|
| `0` | pass |
| `1` | finding |
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
    missing file, a manifest with no tools, or a crash. Before, these exited
    `1` (with a traceback), or `0` when an empty manifest SHIPped.
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
    `autonomous` and `INFER:` lines are gone.
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
- **Pre-commit hook**
  - It matches `*.tools.json` and `*dump*.json`.
  - **It no longer matches `.mcp.json`.** That file is a server config, not
    a `tools/list` dump, so grading it failed every commit that touched it.
  - Name committed dumps `<server>.tools.json`.
- **`--live` classifier:** when nothing applies, the model must now say so
  with `none` (case and trailing punctuation don't matter). An empty or prose
  reply fails closed. It used to count as a clean result.

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
