"""
secure/baseline/_shell.py — NOT USED.

This module was the first draft of Phase 14's database-facing code,
before "history.py" was chosen as the file's name instead — this
package doesn't shell out to any OS command (unlike every OTHER
package's `_shell.py`, which specifically means "the only place this
package runs a subprocess" — see secure/persistence/_shell.py,
secure/correlate/_shell.py, etc.), so naming this file `_shell.py`
didn't fit the codebase's actual convention. All of its logic now
lives in secure/baseline/history.py, which nothing in this file
duplicates or re-exports. Left as an inert file (rather than deleted)
only because this sandbox can't delete files once written under the
project's workspace folder; nothing imports this module.
"""

from __future__ import annotations
