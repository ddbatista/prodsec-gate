#!/usr/bin/env python3
"""
mcp_fetch.py — capture a real server's tools/list so the gate has something to
vet. Stdlib only; stdio and HTTP.

THE THING TO UNDERSTAND BEFORE USING IT. To discover what a **stdio** MCP
server exposes you must RUN it: `npx -y some-mcp-server` downloads and executes
third-party code on your machine, before you have decided whether to trust it.
The vetting step requires the subject to execute. That is not a flaw in the
plan, it is the shape of the problem -- and it is why this refuses to spawn
anything without --i-will-execute-this, and why the right place to run it is
inside the L13 sandbox with no write access and no egress beyond the server.

    claude --settings '{"sandbox":{"enabled":true,"allowUnsandboxedCommands":false}}'

HTTP servers do not execute anything locally, so they are safe to fetch -- but
you may be handing an untrusted endpoint an auth token, which is the other half
of the same trade.

Wire format (stdio): newline-delimited JSON-RPC.
  --> initialize
  --> notifications/initialized
  --> tools/list
"""
import argparse
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request

PROTOCOL = "2025-06-18"
VERSION = "0.1.0"
CLIENT = {"name": "prodsec-gate", "version": VERSION}


class NeedsAuth(RuntimeError):
    """401 + WWW-Authenticate. This is the MCP authorization spec working as
    designed (L06): the server is a protected resource and is telling you where
    its metadata lives, per RFC 9728. It is not an error in your request."""

    def __init__(self, www_authenticate):
        self.header = www_authenticate
        m = re.search(r'resource_metadata="([^"]+)"', www_authenticate or "")
        self.metadata_url = m.group(1) if m else None
        super().__init__(www_authenticate or "401 without WWW-Authenticate")


def _msgs():
    return (
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": PROTOCOL, "capabilities": {},
                    "clientInfo": CLIENT}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    )


def fetch_stdio(command, timeout=30):
    init, ready, listing = _msgs()
    payload = "".join(json.dumps(m) + "\n" for m in (init, ready, listing))
    p = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True)
    try:
        out, err = p.communicate(payload, timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        raise RuntimeError("server did not answer within %ds" % timeout)
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue                      # servers log to stdout; skip noise
        if msg.get("id") == 2 and "result" in msg:
            return msg
    raise RuntimeError("no tools/list response.\nstderr: %s" % (err or "")[:400])


def fetch_http(url, headers=None, timeout=30):
    init, ready, listing = _msgs()
    hdrs = {"Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            # Without this, urllib sends "Python-urllib/3.x" and CDNs in front
            # of real MCP servers fingerprint-block it: mcp.sentry.dev returned
            # Cloudflare "Error 1010: blocked based on your browser's
            # signature" (403), which reads as the SERVER refusing you when it
            # is a CDN that never let the request through. Found 2026-09-21.
            "User-Agent": "prodsec-gate/%s (+MCP tools/list vetting)" % VERSION,
            "MCP-Protocol-Version": PROTOCOL}
    hdrs.update(headers or {})

    def post(msg):
        req = urllib.request.Request(url, data=json.dumps(msg).encode(),
                                     headers=hdrs, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read().decode()
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise NeedsAuth(e.headers.get("WWW-Authenticate") or "")
            if e.code == 403:
                raise RuntimeError(
                    "403 from %s. If the body mentions Cloudflare error 1010 "
                    "this is a CDN fingerprint block, not the server: the "
                    "request never reached it." % url)
            raise
        for line in body.splitlines():          # tolerate SSE framing
            line = line[6:] if line.startswith("data: ") else line
            line = line.strip()
            if line.startswith("{"):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    pass
        return None

    post(init)
    post(ready)
    got = post(listing)
    if not got or "result" not in got:
        raise RuntimeError("no tools/list response: %s" % str(got)[:300])
    return got


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="prodsec-fetch",
        description="Capture an MCP server's tools/list as a dump for prodsec-gate.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--stdio", nargs=argparse.REMAINDER,
                   help="command to spawn, e.g. --stdio npx -y @scope/server")
    g.add_argument("--http", help="server URL")
    ap.add_argument("--header", action="append", default=[],
                    help="extra HTTP header, 'Name: value'")
    ap.add_argument("--i-will-execute-this", action="store_true",
                    help="required for --stdio: you are running third-party code")
    a = ap.parse_args(argv)

    try:
        if a.stdio:
            if not a.i_will_execute_this:
                print("REFUSED: --stdio runs the server's own code on this machine,\n"
                      "which is the thing you have not vetted yet. Re-run with\n"
                      "--i-will-execute-this, ideally inside the sandbox:\n"
                      "  claude --settings '{\"sandbox\":{\"enabled\":true,"
                      "\"allowUnsandboxedCommands\":false}}'", file=sys.stderr)
                return 2
            dump = fetch_stdio(a.stdio)
        else:
            headers = dict(h.split(":", 1) for h in a.header)
            dump = fetch_http(a.http, {k: v.strip() for k, v in headers.items()})
    except NeedsAuth as e:
        # Only claim what the server actually sent. api.anthropic.com returns
        # 401 with an EMPTY WWW-Authenticate, and the original wording promised
        # "a pointer to its metadata" above a blank line -- describing the spec
        # instead of the response. Found 2026-09-21 when the learner asked
        # whether any of this output was hardcoded; the answer was no, but the
        # message asserted more than had been observed.
        if e.metadata_url:
            print("AUTH REQUIRED — and this is the MCP authorization spec working,\n"
                  "not a failure. The server is an OAuth 2.1 protected resource and\n"
                  "answered 401 with a pointer to its metadata (RFC 9728):\n"
                  "  WWW-Authenticate: %s\n"
                  "  resource metadata: %s" % (e.header, e.metadata_url),
                  file=sys.stderr)
        elif e.header:
            print("AUTH REQUIRED. The server answered 401 with:\n"
                  "  WWW-Authenticate: %s\n"
                  "No resource_metadata parameter, so there is no RFC 9728\n"
                  "discovery pointer to follow — you need the token by other means."
                  % e.header, file=sys.stderr)
        else:
            print("AUTH REQUIRED. The server answered 401 with an EMPTY\n"
                  "WWW-Authenticate header, so it is telling you nothing about how\n"
                  "to authenticate. That is a gap in the server, not in this tool:\n"
                  "the MCP spec has it SHOULD carry resource_metadata (RFC 9728).",
                  file=sys.stderr)
        print("\nEasiest path: let Claude Code hold the token.\n"
              "  claude mcp add --transport http <name> %s\n"
              "  claude mcp login <name>\n"
              "Then pass your own token here with --header 'Authorization: Bearer ...'"
              % a.http, file=sys.stderr)
        return 2
    except Exception as e:
        print("ERROR: %s: %s" % (type(e).__name__, e), file=sys.stderr)
        return 2

    json.dump(dump, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
