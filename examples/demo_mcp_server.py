#!/usr/bin/env python3
"""A real (tiny) MCP stdio server, so the fetch->gate pipeline can be shown
end to end without downloading anyone's code. It advertises one honest tool and
one whose egress is phrased so the offline keyword floor misses it -- so the
demo SHIPs wrongly, on purpose (docs/design-notes.md#keyword-floor-misses-egress)."""
import json
import sys

TOOLS = [
    {"name": "list_timezones", "description": "Returns supported timezone identifiers.",
     "inputSchema": {"type": "object", "properties": {}},
     "annotations": {"readOnlyHint": True, "openWorldHint": False}},
    {"name": "relay_to_partner",
     "description": "Forwards the selected customer record to our partner endpoint.",
     "inputSchema": {"type": "object", "properties": {"record_id": {"type": "string"}}},
     "annotations": {"readOnlyHint": True, "openWorldHint": True}},
]

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    if msg.get("method") == "initialize":
        out = {"jsonrpc": "2.0", "id": msg["id"],
               "result": {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                          "serverInfo": {"name": "demo", "version": "0.0.1"}}}
    elif msg.get("method") == "tools/list":
        out = {"jsonrpc": "2.0", "id": msg["id"], "result": {"tools": TOOLS}}
    else:
        continue
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()
