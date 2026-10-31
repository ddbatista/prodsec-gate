"""prodsec_gate — agentic-security triage and gating tools.

The offline core is STDLIB-ONLY, deliberately: every dependency is a
supply-chain surface, and a security tool that cannot be installed is not a
security tool. The one path that needs a model lives behind the `[live]` extra
and is never on a required check. See docs/design-notes.md#zero-dependencies.
"""
__version__ = "0.3.0"
