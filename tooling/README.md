# tooling/

> **This file documents `triage.py` and `mcp_adapter.py` as built in lessons
> 03–04.** Since then the workspace shipped a package. Start at the
> [root README](../README.md); per-tool docs for the newer commands are in
> [`docs/`](../docs/):
> [prodsec-gate](../docs/prodsec-gate.md) ·
> [prodsec-fetch](../docs/prodsec-fetch.md) ·
> [packaging & CI](../docs/packaging-and-ci.md).

# agent-triage

A static reviewer for agentic systems. Reads an agent manifest, tags the
trifecta legs, applies the Rule of Two (+ irreversibility override), and maps
findings to the OWASP Top 10 for Agentic Applications (2026).

Built in Lesson 03.

## Run

```sh
python3 triage.py sample-agent.json        # trifecta → GATE
python3 triage.py delete-db-agent.json      # 2 legs but irreversible → GATE
python3 triage.py delete-db-agent-fixed.json # hardened → SHIP

# Audit a real MCP server's advertised tools (Lesson 04):
python3 mcp_adapter.py mcp-dump.json                       # inferred manifest + INFER notes
python3 mcp_adapter.py mcp-dump.json | python3 triage.py - # full audit (reads stdin via "-")
```

No dependencies — Python 3 stdlib only. Exit code is `1` for GATE/REVIEW so it
can fail a CI pipeline; `0` for SHIP.

`mcp_adapter.py` infers trifecta capabilities from a raw MCP `tools/list` dump
(name + description lead; annotations are treated as **untrusted** and a
contradiction between an annotation and the inferred behaviour is flagged).
Inference is lossy — the manifest it emits is a reviewed starting point.

## Manifest schema

```json
{
  "agent": "name",
  "description": "what it does",
  "autonomous": true,
  "human_in_loop": false,
  "tools": [
    {
      "name": "tool_name",
      "description": "...",
      "capabilities": ["untrusted_input", "private_data",
                       "external_comms", "state_change"],
      "reversible": true,
      "scope": "least-privilege description, or null"
    }
  ]
}
```

### Capabilities → trifecta legs
| capability | leg |
|---|---|
| `untrusted_input` | ① untrusted content |
| `private_data` | ② private data |
| `external_comms` / `state_change` | ③ state-change or external comms |

`reversible: false` on a `state_change` tool triggers the irreversibility
override (GATE regardless of leg count). A privileged tool with no `scope`
raises an ASI03 least-privilege finding.

## Getting a real `tools/list` dump

Use the official **MCP Inspector** — it does the `initialize` → `tools/list`
JSON-RPC handshake for you. Two cases depending on how the server ships:

**Local stdio server** (Inspector launches it as a child process):
```sh
npx @modelcontextprotocol/inspector --cli npx <server-pkg> --method tools/list > dump.json
python3 mcp_adapter.py dump.json | python3 triage.py -
```
- ⚠️ This **executes the server's code** to inspect it → supply-chain risk (ASI04).
  Run untrusted servers in a container/VM, not on your workstation.

**Remote HTTP server** (e.g. Wiz: `https://mcp.app.wiz.io/`):
```sh
npx @modelcontextprotocol/inspector   # web UI: Transport=HTTP, set URL, auth, open Tools panel
```
- Needs the server enabled + auth (OAuth, or service-account creds such as
  WIZ_CLIENT_ID / WIZ_CLIENT_SECRET / WIZ_DATACENTER).
- ✅ You do **not** run their code (lower supply-chain risk) — but you hand a
  credential into a live tenant. Least-privilege the API scopes; a read-only
  audit client needs no write access.

Either way: export the JSON, then feed it to `mcp_adapter.py`.

## Roadmap (where this is going)
- Ingest real configs (MCP server tool lists, framework agent definitions) instead of hand-written manifests.
- Cover more of the OWASP ASI set (memory poisoning, inter-agent comms).
- Emit SARIF/JSON for CI dashboards.
