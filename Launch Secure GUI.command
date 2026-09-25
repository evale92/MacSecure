#!/bin/bash
# Launch Secure GUI — double-click in Finder.
# Resolves the project directory from this script's own location, so it
# keeps working if the project moves.

PROJECT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
VENV="$PROJECT_DIR/.venv-tk"

if [ ! -x "$VENV/bin/python3" ]; then
    echo "Missing $VENV — the GUI needs a Python with tkinter."
    echo "Create it with:  brew install python-tk@3.14 && python3.14 -m venv .venv-tk"
    echo "Then:            .venv-tk/bin/pip install -r requirements.txt"
    read -n 1 -s -r -p "Press any key to close."
    exit 1
fi

cd "$PROJECT_DIR" || exit 1
exec "$VENV/bin/python3" secure_gui.py
