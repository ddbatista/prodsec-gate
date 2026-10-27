"""_cli — the exit-code contract, implemented once.

    0  SHIP / pass
    1  GATE / finding
    2  ERROR / NOT AUDITED -- bad input, nothing to audit, or a crash

A gate that passes when it did not run is worse than no gate, because something
downstream believes it. So every "could not look" path ends in 2, and a crash
must never share an exit code with a finding.
"""
import functools
import json
import sys

SHIP, GATE, ERROR = 0, 1, 2


class NotAudited(Exception):
    """Raised for any input problem; the wrapper turns it into exit 2."""


def entrypoint(main):
    """Wrap a command's main() so nothing but its own return value means 0 or 1.

    Python exits 1 on an uncaught exception -- the same code as GATE -- so a
    crash would read as a finding about the subject. NotAudited and any other
    exception become a one-line ERROR on stderr and exit 2. SystemExit (argparse
    usage errors, already 2) passes through untouched. A main() that returns
    anything other than 0, 1 or 2 -- typically None, from falling off its end --
    never reached a verdict, and sys.exit(None) would otherwise mean SHIP.
    """
    @functools.wraps(main)
    def wrapped(*args, **kwargs):
        try:
            rc = main(*args, **kwargs)
            if rc in (SHIP, GATE, ERROR):
                return rc
            print("ERROR: command returned %r instead of a verdict; nothing\n"
                  "       was audited." % (rc,), file=sys.stderr)
        except NotAudited as e:
            print("ERROR: %s" % e, file=sys.stderr)
        except Exception as e:
            print("ERROR: internal error, nothing was audited: %s: %s\n"
                  "       This is a crash, not a verdict about the input."
                  % (type(e).__name__, e), file=sys.stderr)
        return ERROR
    return wrapped


def read_json(path):
    """Load JSON from a path, or from stdin when path is '-'.

    Raises NotAudited with an actionable message for a missing file, empty
    input or malformed JSON.
    """
    try:
        if path == "-":
            raw = sys.stdin.read()
        else:
            with open(path) as f:
                raw = f.read()
    except OSError as e:
        raise NotAudited("cannot read input: %s" % e)
    # Empty input almost always means the UPSTREAM command failed and the pipe
    # swallowed it; "not JSON" would send you looking in the wrong place.
    if not raw.strip():
        raise NotAudited(
            "no input.\n"
            "       If you piped this, the upstream command produced nothing --\n"
            "       read ITS error, not this one. Shells return only the LAST\n"
            "       exit code in a pipeline, so add:  set -o pipefail")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        raise NotAudited("input is not JSON: %s" % e)
