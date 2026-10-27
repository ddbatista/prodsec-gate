"""Shared test helpers: run a command the way CI does, and the fixture paths."""
import atexit
import contextlib
import io
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLING = os.path.join(ROOT, "tooling")

SHIP, GATE, ERROR = 0, 1, 2

FIXTURES = os.path.join("tests", "fixtures")
VULNERABLE = os.path.join("tooling", "mcp-dump.json")
HARMLESS = os.path.join(FIXTURES, "harmless.tools.json")

# The auditors read ~/.claude etc. Point HOME at an empty directory so a
# developer's real config can neither pass nor fail these tests. Removed at
# interpreter exit, not per module: every test module shares it.
EMPTY_HOME = tempfile.mkdtemp(prefix="prodsec-home-")
atexit.register(shutil.rmtree, EMPTY_HOME, ignore_errors=True)


def run(script, *args, stdin=""):
    """Run tooling/<script>.py the way a CI job would; return the CompletedProcess."""
    env = dict(os.environ, HOME=EMPTY_HOME)
    return subprocess.run(
        [sys.executable, os.path.join(TOOLING, script + ".py")] + list(args),
        input=stdin, capture_output=True, text=True, cwd=ROOT, env=env, timeout=60)


def gate_in_process(argv, backend, stdin="", stderr=False):
    """Run gate.main with an injected backend -- the --live path, minus the network.

    Returns (exit code, stdout), or (exit code, stdout, stderr) with stderr=True.
    """
    sys.path.insert(0, TOOLING)
    import gate
    out, err = io.StringIO(), io.StringIO()
    old_stdin = sys.stdin
    sys.stdin = io.StringIO(stdin)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = gate.main(argv, backend=backend)
    finally:
        sys.stdin = old_stdin
    return (rc, out.getvalue(), err.getvalue()) if stderr else (rc, out.getvalue())
