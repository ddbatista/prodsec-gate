"""An MCP stdio server that behaves like the Python MCP SDK in two ways:

  * it shuts down on stdin EOF and drops any request still in flight, so a
    client that writes every message and closes stdin never gets tools/list;
  * it pages tools/list: the first page carries a nextCursor.
"""
import json
import sys
import threading
import time

eof = threading.Event()
lines = []
lock = threading.Lock()


def reader():
    for line in sys.stdin:
        with lock:
            lines.append(line)
    eof.set()


threading.Thread(target=reader, daemon=True).start()
PAGES = {None: ([{"name": "page_one", "description": "First page."}], "p2"),
         "p2": ([{"name": "page_two", "description": "Second page."}], None)}

while True:
    with lock:
        line = lines.pop(0) if lines else None
    if line is None:
        if eof.is_set():
            sys.exit(0)
        time.sleep(0.01)
        continue
    msg = json.loads(line)
    if msg.get("method") == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                  "serverInfo": {"name": "eof-sensitive", "version": "0"}}
    elif msg.get("method") == "tools/list":
        time.sleep(0.2)                       # in flight...
        if eof.is_set():
            sys.exit(0)                       # ...and dropped, like the SDK
        tools, cursor = PAGES[(msg.get("params") or {}).get("cursor")]
        result = {"tools": tools}
        if cursor:
            result["nextCursor"] = cursor
    else:
        continue
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}) + "\n")
    sys.stdout.flush()
