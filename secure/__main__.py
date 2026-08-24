"""
Lets you run the package directly with:

    python -m secure <command>

instead of installing it first. This file just hands off to the real
CLI logic in secure/cli.py.
"""

from secure.cli import main

if __name__ == "__main__":
    main()
