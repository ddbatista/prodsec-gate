#!/usr/bin/env python3
"""
capture.py — (re)capture the real-server corpus from corpus/sources.json.

Maintainer tool, not shipped. The corpus fixtures are committed, so the eval
and the ratchet never run this; only rebuilding the corpus does.

Every capture follows the same order, so no third-party code runs unconfined:

  1. decide the licence from registry metadata (or a commit-pinned licence
     file) and refuse anything non-permissive BEFORE anything is downloaded;
  2. install the pinned version with install scripts disabled (npm
     --ignore-scripts; pip wheels only), so installing executes nothing;
  3. run the server inside corpus/sandbox.sb (macOS sandbox-exec: no network,
     no Mach services or AppleEvents, an exec allow-list, no reads of user
     data, writes only in a throwaway directory) with a replaced environment,
     just long enough to answer tools/list;
  4. write corpus/servers/<server>.json, keeping existing labels for tools
     that are still there. A new or renamed tool is left unlabelled, so the
     schema test fails until a human labels it.

Only macOS is supported. Elsewhere it refuses (exit 2) rather than run a
server without a sandbox.

    python3 corpus/capture.py              # every source
    python3 corpus/capture.py filesystem   # just these
"""
import argparse
import datetime
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "tooling"))

import _cli                      # noqa: E402
import eval_adapter as E         # noqa: E402
import mcp_fetch                 # noqa: E402

SOURCES = os.path.join(HERE, "sources.json")
SERVERS = os.path.join(HERE, "servers")
PROFILE = os.path.join(HERE, "sandbox.sb")

# What a LICENSE file must say for each SPDX id, when the registry only
# points at the file ("SEE LICENSE IN LICENSE").
LICENCE_TEXT = {
    "MIT": "MIT License",
    "Apache-2.0": "Apache License",
}


def sh(cmd, **kw):
    p = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if p.returncode:
        raise RuntimeError("%s failed (exit %d): %s"
                           % (" ".join(cmd[:3]), p.returncode, p.stderr.strip()[-400:]))
    return p.stdout


def npm_meta(src):
    d = json.loads(sh(["npm", "view", "%s@%s" % (src["package"], src["version"]),
                       "version", "license", "repository.url", "--json"]))
    return d["version"], d.get("license") or "", d.get("repository.url") or ""


def pypi_meta(src):
    url = "https://pypi.org/pypi/%s/%s/json" % (src["package"], src["version"])
    with urllib.request.urlopen(url, timeout=30) as r:
        info = json.load(r)["info"]
    lic = info.get("license_expression") or info.get("license") or ""
    urls = info.get("project_urls") or {}
    return info["version"], lic, urls.get("Source") or urls.get("Repository") or ""


def licence_of(registry_licence, src):
    """The SPDX expression to record, decided BEFORE anything is downloaded.

    The registry's own field wins when it is permissive. When it only points
    at a file ("SEE LICENSE IN LICENSE"), src must name the licence and give
    a licence_url, pinned to a commit, whose text names every licence in it.
    """
    if E.licence_ok(registry_licence):
        return registry_licence
    claimed = src.get("licence")
    if not E.licence_ok(claimed) or not src.get("licence_url"):
        raise RuntimeError("licence %r is not on the permissive list; nothing downloaded"
                           % registry_licence)
    with urllib.request.urlopen(src["licence_url"], timeout=30) as r:
        text = r.read().decode("utf-8", "replace")
    for i in E.licence_ids(claimed):
        if i not in LICENCE_TEXT or LICENCE_TEXT[i] not in text:
            raise RuntimeError("registry says %r and %s does not confirm %s; nothing "
                               "downloaded" % (registry_licence, src["licence_url"], i))
    return claimed


def install_npm(src, version, work):
    sh(["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund",
        "--no-save", "--prefix", work, "%s@%s" % (src["package"], version)])
    pkg_dir = os.path.join(work, "node_modules", *src["package"].split("/"))
    pj = json.load(open(os.path.join(pkg_dir, "package.json")))
    bins = pj["bin"] if isinstance(pj["bin"], dict) else {pj["name"]: pj["bin"]}
    entry = os.path.join(pkg_dir, bins[src.get("bin") or sorted(bins)[0]])
    node = os.path.realpath(shutil.which("node"))
    return [node, entry], os.path.dirname(os.path.dirname(node))


def install_pypi(src, version, work):
    site = os.path.join(work, "site")
    sh([sys.executable, "-m", "pip", "install", "--quiet", "--only-binary=:all:",
        "--no-compile", "--target", site, "%s==%s" % (src["package"], version)])
    boot = ("import runpy, sys; sys.path.insert(0, %r); "
            "runpy.run_module(%r, run_name='__main__')" % (site, src["module"]))
    return [os.path.realpath(sys.executable), "-c", boot], os.path.realpath(sys.base_prefix)


REGISTRIES = {"npm": (npm_meta, install_npm), "pypi": (pypi_meta, install_pypi)}


def check_runtime(runtime, guarded):
    """The sandbox lets the server read all of RUNTIME. Refuse a RUNTIME that
    would re-open what the profile closes (a node in ~/bin makes it ~)."""
    for g in guarded:
        if os.path.commonpath([runtime, g]) == runtime:
            raise RuntimeError("runtime directory %s contains %s; the sandbox would "
                               "let the server read it" % (runtime, g))


def capture(src):
    meta, install = REGISTRIES[src["registry"]]
    version, lic, repo = meta(src)
    licence = licence_of(lic, src)

    work = os.path.realpath(tempfile.mkdtemp(prefix="prodsec-capture-"))
    temp = os.path.dirname(work)
    home = os.path.realpath(os.path.expanduser("~"))
    try:
        cmd, runtime = install(src, version, work)
        check_runtime(runtime, [home, "/Users", temp])
        for d in ("home", "tmp", "root"):
            os.makedirs(os.path.join(work, d))
        args = [a.replace("{ROOT}", os.path.join(work, "root")) for a in src.get("args", [])]
        env = {"PATH": "/usr/bin:/bin", "HOME": os.path.join(work, "home"),
               "TMPDIR": os.path.join(work, "tmp"), "LANG": "C.UTF-8"}
        env.update(src.get("env", {}))
        # env -i: the server sees only these variables, never the maintainer's.
        sandboxed = (["/usr/bin/env", "-i"] + ["%s=%s" % kv for kv in sorted(env.items())]
                     + ["/usr/bin/sandbox-exec", "-f", PROFILE, "-D", "WORK=" + work,
                        "-D", "RUNTIME=" + runtime, "-D", "TEMP=" + temp]
                     + cmd + args)
        # Start inside WORK: a server whose working directory the sandbox
        # will not let it read dies before it answers.
        dump = mcp_fetch.fetch_stdio(sandboxed, timeout=src.get("timeout", 60), cwd=work)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    tools = dump["result"]["tools"]
    path = os.path.join(SERVERS, src["server"] + ".json")
    old = json.load(open(path)) if os.path.exists(path) else {}
    old_labels = old.get("labels", {})
    fx = {
        "server": src["server"],
        "package": src["package"],
        "registry": src["registry"],
        "version": version,
        "source": src.get("source") or repo,
        "licence": licence,
        "captured": datetime.date.today().isoformat(),
        "capture_method": "sandboxed-stdio",
        "capture_args": src.get("args", []),
        "notes": src.get("notes", ""),
        "tools": tools,
        "labels": {t["name"]: old_labels[t["name"]] for t in tools if t["name"] in old_labels},
        "expected_verdict": old.get("expected_verdict", ""),
        "rationale": old.get("rationale", ""),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(fx, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return fx


@_cli.entrypoint
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("servers", nargs="*", help="server names from sources.json; default all")
    a = ap.parse_args(argv)
    if sys.platform != "darwin" or not shutil.which("sandbox-exec"):
        raise _cli.NotAudited("capture needs macOS sandbox-exec; refusing to run "
                              "third-party servers unsandboxed")
    sources = json.load(open(SOURCES))
    chosen = [s for s in sources if not a.servers or s["server"] in a.servers]
    unknown = set(a.servers) - {s["server"] for s in sources}
    if unknown:
        raise _cli.NotAudited("not in sources.json: %s" % ", ".join(sorted(unknown)))
    failed = 0
    for src in chosen:
        sys.stdout.flush()
        try:
            fx = capture(src)
            missing = len(fx["tools"]) - len(fx["labels"])
            print("  ok    %-22s %s@%s  %d tools%s" % (
                src["server"], fx["package"], fx["version"], len(fx["tools"]),
                "  (%d unlabelled)" % missing if missing else ""))
        except Exception as e:
            failed += 1
            msg = str(e).strip().splitlines()
            print("  FAIL  %-22s %s" % (src["server"], msg[0] if msg else type(e).__name__))
            for line in msg[1:6]:
                print("        %s" % line)
    return _cli.ERROR if failed else _cli.SHIP


if __name__ == "__main__":
    sys.exit(main())
