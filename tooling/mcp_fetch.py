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
inside the Claude Code sandbox with no write access and no egress beyond the
server. See docs/design-notes.md#fetch-executes-code.

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
import os
import queue
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _cli                      # noqa: E402

PROTOCOL = "2025-06-18"
VERSION = "0.2.0"
CLIENT = {"name": "prodsec-gate", "version": VERSION}


class NeedsAuth(RuntimeError):
    """401 + WWW-Authenticate. This is the MCP authorization spec working as
    designed: the server is a protected resource and is telling you where
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
    """Talk to the server one request at a time, keeping stdin open until the
    last answer. Writing everything and closing stdin is not enough: the
    Python MCP SDK shuts down on EOF and drops the request still in flight.
    Follows tools/list pagination (nextCursor)."""
    init, ready, listing = _msgs()
    p = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True)
    lines, err = queue.Queue(), []
    threading.Thread(target=lambda: [lines.put(x) for x in p.stdout] + [lines.put(None)],
                     daemon=True).start()
    threading.Thread(target=lambda: err.extend(p.stderr), daemon=True).start()
    deadline = time.monotonic() + timeout

    def send(msg):
        p.stdin.write(json.dumps(msg) + "\n")
        p.stdin.flush()

    def answer(want):
        while True:
            try:
                line = lines.get(timeout=max(0.0, deadline - time.monotonic()))
            except queue.Empty:
                raise RuntimeError("server did not answer within %ds" % timeout)
            if line is None:
                time.sleep(0.1)           # let stderr drain for the message
                raise RuntimeError("no tools/list response.\nstderr: %s"
                                   % "".join(err)[:400])
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue                  # servers log to stdout; skip noise
            if isinstance(msg, dict) and msg.get("id") == want:
                if "result" not in msg:
                    raise RuntimeError("server answered with an error: %s"
                                       % json.dumps(msg.get("error"))[:400])
                return msg

    try:
        send(init)
        answer(init["id"])
        send(ready)
        send(listing)
        first = answer(listing["id"])
        tools = list(first["result"].get("tools", []))
        cursor, n = first["result"].get("nextCursor"), listing["id"]
        while cursor:
            n += 1
            send({"jsonrpc": "2.0", "id": n, "method": "tools/list",
                  "params": {"cursor": cursor}})
            page = answer(n)["result"]
            tools += page.get("tools", [])
            cursor = page.get("nextCursor")
    except (BrokenPipeError, OSError) as e:
        raise RuntimeError("server exited early (%s).\nstderr: %s"
                           % (e, "".join(err)[:400]))
    finally:
        try:
            p.stdin.close()
        except OSError:
            pass
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
    first["result"]["tools"] = tools
    first["result"].pop("nextCursor", None)
    return first


def fetch_http(url, headers=None, timeout=30):
    init, ready, listing = _msgs()
    hdrs = {"Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            # Without this, urllib sends "Python-urllib/3.x" and CDNs in front
            # of real MCP servers fingerprint-block it with a 403 that reads as
            # the SERVER refusing you, when a CDN never let the request through.
            # See docs/design-notes.md#fetch-executes-code.
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


@_cli.entrypoint
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
                return _cli.ERROR
            dump = fetch_stdio(a.stdio)
        else:
            headers = dict(h.split(":", 1) for h in a.header)
            dump = fetch_http(a.http, {k: v.strip() for k, v in headers.items()})
    except NeedsAuth as e:
        # Only claim what the server actually sent: some servers answer 401
        # with an EMPTY WWW-Authenticate, and the message must describe the
        # response, not the spec. See docs/design-notes.md#fetch-executes-code.
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
        return _cli.ERROR
    except Exception as e:
        print("ERROR: %s: %s" % (type(e).__name__, e), file=sys.stderr)
        return _cli.ERROR

    json.dump(dump, sys.stdout, indent=2)
    print()
    return _cli.SHIP


if __name__ == "__main__":
    sys.exit(main())
