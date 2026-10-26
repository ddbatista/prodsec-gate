# prodsec-fetch

Capture a live MCP server's `tools/list` so the gate has something real to vet.
Stdio and HTTP. Stdlib only.

Source: [`tooling/mcp_fetch.py`](../tooling/mcp_fetch.py) · Built in Capstone D1.

## The thing to understand first

**To discover what a stdio MCP server exposes, you must run it.**
`npx -y some-mcp-server` downloads and executes third-party code on your
machine, before you have decided whether to trust it. The vetting step requires
the subject to execute. That is not a flaw in the plan; it is the shape of the
problem.

So stdio fetches refuse without explicit consent:

```
REFUSED: --stdio runs the server's own code on this machine,
which is the thing you have not vetted yet.
```

Do the first fetch of an unknown server inside the sandbox:

```sh
claude --settings '{"sandbox":{"enabled":true,"allowUnsandboxedCommands":false}}'
```

HTTP servers execute nothing locally — but you may be handing an unvetted
endpoint an auth token, which is the same trade from the other side.

## Usage

```sh
# stdio — RUNS the server
prodsec-fetch --i-will-execute-this --stdio npx -y @scope/server > dump.json

# HTTP — nothing executes locally
prodsec-fetch --http https://example.com/mcp > dump.json
prodsec-fetch --http https://example.com/mcp --header "Authorization: Bearer $TOK"

# straight into the gate
set -o pipefail
prodsec-fetch --http https://example.com/mcp | prodsec-gate -
```

Try it end to end with no third-party code at all:

```sh
prodsec-fetch --i-will-execute-this --stdio python3 examples/demo_mcp_server.py \
  | prodsec-gate -
```

## Wire format

Newline-delimited JSON-RPC, three messages:

```
--> initialize                 (protocolVersion 2025-06-18)
--> notifications/initialized
--> tools/list
```

Emits the raw `tools/list` response, which `prodsec-gate` consumes directly.

## Errors you will actually hit

**`403` with Cloudflare "Error 1010"** — a CDN fingerprint block, *not the
server*. The request never arrived. `prodsec-fetch` sends a real `User-Agent`
to avoid it; if you see 1010 anyway, the CDN is refusing your client, not
refusing your credentials.

**`401` with `WWW-Authenticate: Bearer ... resource_metadata="..."`** — this is
the MCP authorization spec working as designed, not a failure. The server is an
OAuth 2.1 protected resource pointing at its metadata per RFC 9728:

```
claude mcp add --transport http <name> <url>
claude mcp login <name>
# then pass the token yourself:
prodsec-fetch --http <url> --header "Authorization: Bearer $TOK"
```

**Empty output into `prodsec-gate`** — the fetch failed and the pipe swallowed
it. Shells report only the last command's exit code. **`set -o pipefail`.**

## Exit codes

| Code | Meaning |
|---|---|
| `0` | dump written to stdout |
| `2` | refused (no `--i-will-execute-this`), auth required, transport error, or no `tools/list` in the reply |

## Limitations

- **No OAuth flow.** It surfaces the 401 and the metadata URL; obtaining a
  token is left to `claude mcp login` or your own client.
- **No HTTP session handling.** It does not track `Mcp-Session-Id`; servers
  that require a session across the three messages may reject the sequence.
- **stdio stdout is assumed to be the transport.** Servers that log
  non-JSON to stdout are tolerated (non-JSON lines are skipped), but a server
  that interleaves framing differently will not parse.
