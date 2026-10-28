# Real-server corpus

The `tools/list` output of real public MCP servers, each tool labelled by hand.
The eval scores the gate's keyword floor against these labels, and a ratchet
test fails if recall drops below the committed baseline:

```sh
python3 tooling/eval_adapter.py --servers corpus/servers   # the report
python -m unittest tests.test_corpus                       # schema + ratchet
```

The fixtures are committed, so neither command runs any server.

## Files

| Path | What it is |
|---|---|
| `servers/<server>.json` | One captured server: provenance, tools, labels, expected verdict |
| `sources.json` | What to capture: package, pinned version, arguments |
| `capture.py` | Re-captures servers from `sources.json` (macOS only, see below) |
| `sandbox.sb` | The `sandbox-exec` profile every stdio capture runs under |
| `baseline.json` | The recall floor the ratchet holds |

## Fixture schema

```jsonc
{
  "server": "filesystem",                 // file name, without .json
  "package": "@modelcontextprotocol/server-filesystem",
  "registry": "npm",                      // npm or pypi
  "version": "2.0.1",                     // exact, never a range
  "source": "https://github.com/...",     // where the code lives
  "licence": "MIT AND Apache-2.0",        // SPDX; every id must be permissive
  "captured": "2026-10-27",
  "capture_method": "sandboxed-stdio",    // or remote-http
  "capture_args": ["{ROOT}"],             // server arguments; {ROOT} is a scratch dir
  "notes": "",
  "tools": [ /* tools/list result, verbatim */ ],
  "labels": {
    "write_file": {
      "capabilities": ["state_change"],   // ground truth, see below
      "reversible": false,                // only for state_change; else null
      "why": "overwrites an existing file in place; no undo"
    }
  },
  "expected_verdict": "GATE",             // SHIP or GATE: a policy label
  "rationale": "one line: why a reviewer would or would not let it run unattended"
}
```

`tests/test_corpus.py` validates every fixture: provenance present, licence
permissive, one label per captured tool and no others, capabilities from the
vocabulary below, `reversible` set exactly when the tool changes state, and a
`why` on every label.

## Labelling rules

Labels record what a tool **does**, judged from its description, its input
schema and, where those are unclear, its source. They are never read from the
keyword patterns, and annotations are evidence, not truth.

| Capability | Label it when the tool… |
|---|---|
| `untrusted_input` | returns **content** that someone other than the user may have authored: web pages, files of unknown origin, issues, messages, search results, stored memory written from earlier sessions. Names, sizes and other metadata do not count. |
| `private_data` | returns or reveals data that is not public: local files and their names, private repositories, database rows, messages, account details, stored memory. |
| `external_comms` | can send data somewhere the user does not control or others can read: requests to arbitrary URLs (a GET's URL is a channel), posting messages, comments or issues, sending email, uploading. Writing a local file is not egress. |
| `state_change` | changes persistent state anywhere: files, databases, remote resources, stored memory. Reading, listing and pure computation do not. |

`reversible` (only with `state_change`): `true` when the user can undo the
change with the same server or ordinary means and nothing is lost, such as
creating something that can be deleted or a move that can be moved back.
`false` when data is destroyed or replaced (delete, overwrite, in-place edit)
or the effect has already left the user's hands (a sent message).

**Expected verdict** is a separate, human policy call: would a careful
reviewer let an agent with exactly this server run unattended? It is recorded
so the eval can tell a **detection** miss (the legs were wrong) from a
**policy** question (right legs, but the triage rules and the reviewer
disagree). A policy question is never fixed by weakening a pattern.

## Capturing

```sh
python3 corpus/capture.py              # every entry in sources.json
python3 corpus/capture.py time memory  # just these
```

For each server, in this order:

1. **Licence, before download.** The registry metadata must name a
   permissive licence. When it only points at a file ("SEE LICENSE IN
   LICENSE"), `sources.json` must state the licence and the file's text,
   in the package or at `licence_url`, must confirm it.
2. **Install without running anything.** npm runs with `--ignore-scripts`;
   pip takes wheels only. Installing executes no package code.
3. **Run sandboxed.** The server starts under `sandbox.sb`: no network, no
   reads under `$HOME` except the Node or Python runtime, writes only in a
   throwaway directory. Its environment is replaced with a minimal one
   (`env -i`), so it never sees the maintainer's variables or tokens. It runs
   only long enough to answer `tools/list`.
4. **Keep labels.** Labels for tools that are still present are kept. A new
   or renamed tool is left unlabelled, so the schema test fails until someone
   labels it.

`capture.py` needs macOS `sandbox-exec`. On any other OS it refuses (exit 2)
rather than run a server without a sandbox. A Linux port would wrap the same
steps in `bwrap --unshare-net`.

## Licences

Only servers whose licences are all permissive are captured, because the
fixtures redistribute their tool descriptions. Each fixture records its
licence and source. The descriptions remain their authors' work, under those
licences.
