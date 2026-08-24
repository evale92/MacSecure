#!/bin/bash
# Launch Secure GUI.command
#
# Double-click this in Finder: it closes any other Secure GUI window
# still running (so you never end up looking at a stale window with
# old code in memory), opens Terminal, moves into the Secure project
# folder, and starts the GUI control panel (secure_gui.py). Pure
# convenience — it just runs the same things you'd otherwise type by
# hand.

PROJECT_DIR="/Users/Erick/PycharmProjects/Secure"

cd "$PROJECT_DIR" || {
    echo "Could not find the Secure project folder at:"
    echo "  $PROJECT_DIR"
    echo "If you moved the project, edit PROJECT_DIR at the top of this file."
    read -p "Press Enter to close..."
    exit 1
}

# Close any other running Secure GUI session(s) first. The pattern is
# bracketed ("[s]ecure_gui") so pgrep/pkill's own process listing
# doesn't match itself — a standard trick, not specific to this app.
# Sends a polite terminate signal first, waits a moment, then a harder
# kill for anything that ignored it (still no sudo — this only ever
# touches your own processes, same as everything else this app does).
EXISTING_PIDS=$(pgrep -f "[s]ecure_gui\.py")
if [ -n "$EXISTING_PIDS" ]; then
    echo "Closing existing Secure GUI session(s): $EXISTING_PIDS"
    kill $EXISTING_PIDS 2>/dev/null
    sleep 1
    STILL_RUNNING=$(pgrep -f "[s]ecure_gui\.py")
    if [ -n "$STILL_RUNNING" ]; then
        echo "Force-closing session(s) that didn't exit: $STILL_RUNNING"
        kill -9 $STILL_RUNNING 2>/dev/null
    fi
    echo
fi

# Prefer the project's own virtual environment if one exists — same
# logic secure_gui.py itself uses for the commands its buttons run.
if [ -x ".venv/bin/python3" ]; then
    PYTHON_BIN=".venv/bin/python3"
else
    PYTHON_BIN="python3"
fi

echo "Starting Secure GUI using $PYTHON_BIN ..."
echo
"$PYTHON_BIN" secure_gui.py

# Keep the window open after the GUI closes so any error output
# stays visible instead of the Terminal window vanishing immediately.
echo
read -p "Secure GUI closed. Press Enter to close this window..."
