"""
Secure — foundation package for a defensive macOS security application.

This package intentionally contains NO security/monitoring logic yet.
It only provides the plumbing every later feature will need:

    secure.config          -> load/save settings from a JSON file
    secure.logging_setup   -> structured (JSON) logging to file + console
    secure.storage         -> SQLite database + a generic "events" table
    secure.cli             -> command-line entry point

See PROJECT_NOTES.md at the project root for the full explanation of
how these pieces fit together.
"""

__version__ = "0.1.0"
