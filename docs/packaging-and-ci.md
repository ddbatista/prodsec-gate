# Packaging, CI and the pre-commit hook

How the tooling travels. Built in Capstone D1.

## `pyproject.toml`

Declares seven console entry points and, deliberately, **no dependencies**:

```toml
dependencies = []                      # the offline core

[project.optional-dependencies]
live     = ["claude-agent-sdk>=0.2"]   # never in a required check
live-api = ["anthropic>=1.0"]

[project.scripts]
prodsec-gate = "prodsec_gate.gate:main"
...

[tool.setuptools.package-dir]
prodsec_gate = "tooling"              # the package IS tooling/, not a copy
```

The package maps onto `tooling/` rather than duplicating it, so
`pip install -e .` means edits take effect immediately with nothing to keep in
sync.

A console script is not a binary — it is a ~270-byte shim pip writes at install
time that imports `main` and calls `sys.exit` on its return value. That is why
**every command must return an int**, not print and fall off the end.

## Where it ends up

```sh
pip install -e .        # .venv/bin/prodsec-*        (develop here)
pipx install .          # ~/.local/bin/prodsec-*     (use everywhere)
```

Installing into a throwaway venv proves portability and leaves you nothing.
Both were done during D1; only the second is useful afterwards.

## `.github/workflows/prodsec-gate.yml`

Runs the **offline path only**. The rule it encodes:

> A required check must be free, deterministic, offline and fast. The live
> classifier is none of those. **A gate that fails because someone's API quota
> ran out teaches people to bypass gates.**

Three steps, in this order, because the order is the argument:

1. **Self-tests** — a tool whose own tests fail has no standing to grade anything.
2. **End-to-end smoke** — fetch from the bundled demo server and gate it.
3. **Known-vulnerable fixture must GATE** — `tooling/mcp-dump.json` must exit
   exactly `1`. A `0` means detection regressed; a `2` means the check did not
   run. In a consuming repo, gate your real dumps instead, where `exit 2` fails
   the build as hard as `exit 1`.

Also: `permissions: contents: read` at the top, raised per job. That is the L08
finding applied to what we ship.

Run the `--live` pass on a schedule and open an issue on disagreement. Never
block a merge on it.

## `.pre-commit-hooks.yaml`

Lets any repo consume the gate:

```yaml
repos:
  - repo: https://github.com/ddbatista/prodsec-gate
    rev: v0.1.0
    hooks: [{id: prodsec-gate}]
```

**Known weakness, disclosed:** the `files:` selector is a regex over filenames.
That is exactly the class of control this workspace spent August taking apart —
a rule that names a spelling rather than an effect. A dump called
`servers.json` is not matched. Widen the pattern for your repo, or invoke the
gate explicitly in CI where the file list is yours to control.

## `examples/demo_mcp_server.py`

A real (tiny) MCP stdio server, so the fetch → gate pipeline can be demonstrated
without downloading anyone's code. It advertises one honest tool and one whose
description is written the way X3's was — so the demo ends in a `SHIP` that is
*wrong*, which is the point.
