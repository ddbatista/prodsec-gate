"""prodsec_gate — agentic-security tooling built across lessons 01-17.

The offline core is STDLIB-ONLY, deliberately. Every dependency is an ASI04
supply-chain surface and a reason a gate stops running on someone else's
machine; a security tool that cannot be installed is not a security tool.
The one path that needs a model lives behind the `[live]` extra and is never
on a required check.
"""
__version__ = "0.1.0"
