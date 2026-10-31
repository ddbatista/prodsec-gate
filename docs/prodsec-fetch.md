# prodsec-fetch

Capture a live MCP server's `tools/list` so the gate has something real to vet.
Stdio and HTTP. Stdlib only.

Source: [`tooling/mcp_fetch.py`](../tooling/mcp_fetch.py) ·
Why: [design notes](design-notes.md#fetch-executes-code).

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

Do the first fetch of an unknown server inside a sandbox. Two ways:

```sh
# Claude Code's sandbox, around the whole session:
claude --settings '{"sandbox":{"enabled":true,"allowUnsandboxedCommands":false}}'
```

On macOS, [`corpus/sandbox.sb`](../corpus/sandbox.sb) is the profile the
real-server corpus was captured under. It allows no network, no Mach services
or AppleEvents, and runs only the server's runtime and git. It blocks reads of
user data and allows writes only in a scratch directory.
[`corpus/capture.py`](../corpus/capture.py) shows how to run a pinned package
under it, installed with scripts disabled.

HTTP servers execute nothing locally — but you may be handing an unvetted
endpoint an auth token, which is the same trade from the other side.

## Usage

```sh
# stdio — RUNS the server
prodsec-fetch --i-will-execute-this --stdio npx -y @scope/server > dump.json

# a Python server works the same way (install it first)
pip install mcp-server-time
prodsec-fetch --i-will-execute-this --stdio python3 -m mcp_server_time > time.tools.json

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

Newline-delimited JSON-RPC, one request at a time:

```
--> initialize                 (protocolVersion 2025-06-18)
<-- result
--> notifications/initialized
--> tools/list
<-- result                     (and, while it carries nextCursor:)
--> tools/list {cursor}
<-- result
```

stdin stays open until the last answer arrives. A client that writes all
three messages and hangs up gets nothing from a Python MCP server: the SDK
shuts down on EOF and drops the request still in flight. Pages are followed
and merged, so the output is one `tools/list` response holding every tool,
which `prodsec-gate` consumes directly.

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

**`server exited before answering initialize`** — the server crashed on
start, usually because of a missing token or config. The tail of its stderr
follows the message. `server did not answer tools/list within 30s` and
`server answered tools/list with an error: …` name the step the same way.

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
