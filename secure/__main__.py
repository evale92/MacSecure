"""
Lets you run the package directly with:

    python -m secure <command>

instead of installing it first. This file just hands off to main() in
secure/cli/__init__.py, which wires the argparse subcommands to their
handlers in the per-domain modules under secure/cli/.
"""

from secure.cli import main

if __name__ == "__main__":
    main()
