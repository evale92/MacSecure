"""
Tests for scripts/ble_stepzero_check.py (the one-time BLE step-zero
diagnostic).

Why this file exists: before it, nothing in the suite touched
scripts/ at all. Every static sweep in the suite roots somewhere
under secure/ or secure_gui/ — test_clean_install.py's two
rglobs at `_project_root() / "secure"`, test_dfir_adversarial.py's
at secure/, test_agent.py's at secure/agent/, and
test_agent_supervisor.py's at secure_gui/ — so this script was not
imported, not parsed, and not named by any test. A syntax error in
it would not have failed anything.

It also cannot simply be imported: the module runs its whole
diagnostic at import time and calls sys.exit() through verdict().
So it is exercised the only way it is actually used — as a
subprocess — and otherwise checked structurally by parsing it.

The subprocess run must never reach real Bluetooth. It is given a
PYTHONPATH containing stub CoreBluetooth/Foundation/bleak modules
that raise ImportError on import, so whichever of the script's two
import guards is hit first trips before line 122's
CBCentralManager is ever constructed. That makes the run
deterministic on a machine with PyObjC installed and on one
without, and it is what lets this test assert honest absence
(TESTING_POLICY rule 9) rather than a happy path.

The exit-status tests go further with importable fakes that report a
chosen CBCentralManager state and a canned scan result, so every
verdict branch runs — still without any real Bluetooth.

Run with:  pytest
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "ble_stepzero_check.py"

# The five verdict labels the script's own module docstring commits to.
_DOCUMENTED_VERDICTS = {
    "OPERATIONAL_SCAN_OK",
    "OPERATIONAL_ZERO_RESULTS",
    "POWERED_OFF",
    "PERMISSION_DENIED",
    "API_UNAVAILABLE_OR_ERROR",
}

_STUBBED_MODULES = ("CoreBluetooth", "Foundation", "bleak")


def _parse_script() -> ast.Module:
    return ast.parse(_SCRIPT.read_text(encoding="utf-8"), filename=str(_SCRIPT))


def _make_unimportable_stubs(tmp_path: Path) -> Path:
    """A directory of modules that raise ImportError when imported.

    Shadowing all three is deliberate belt-and-braces: the script
    guards CoreBluetooth/Foundation first and bleak second, and both
    guards sit above the CBCentralManager construction, so tripping
    any of them guarantees the test never talks to the radio.
    """
    stub_dir = tmp_path / "stubs"
    stub_dir.mkdir()
    for name in _STUBBED_MODULES:
        (stub_dir / f"{name}.py").write_text(
            f'raise ImportError("{name} is stubbed out by test_ble_stepzero_check")\n',
            encoding="utf-8",
        )
    return stub_dir


_FAKE_MARKER = "FAKE_COREBLUETOOTH_STUB_IN_USE"


def _make_fake_bluetooth(tmp_path: Path, state: int, device_count: int) -> Path:
    """Importable fakes that report `state` and find `device_count` devices.

    These reach every verdict past the import guards without a radio:
    the fake CBCentralManager hands its delegate `state` synchronously,
    and the fake BleakScanner returns canned devices. The import-time
    marker proves the fakes shadowed any real PyObjC/bleak installed.
    """
    stub_dir = tmp_path / f"fakes_{state}_{device_count}"
    stub_dir.mkdir()
    (stub_dir / "Foundation.py").write_text(
        "class NSObject:\n"
        "    @classmethod\n"
        "    def alloc(cls):\n"
        "        return cls()\n"
        "    def init(self):\n"
        "        return self\n"
        "class NSDate:\n"
        "    @staticmethod\n"
        "    def dateWithTimeIntervalSinceNow_(seconds):\n"
        "        return seconds\n"
        "class NSRunLoop:\n"
        "    @staticmethod\n"
        "    def currentRunLoop():\n"
        "        return NSRunLoop()\n"
        "    def runUntilDate_(self, date):\n"
        "        pass\n",
        encoding="utf-8",
    )
    (stub_dir / "CoreBluetooth.py").write_text(
        f"print({_FAKE_MARKER!r})\n"
        "class _Central:\n"
        "    def state(self):\n"
        f"        return {state}\n"
        "class CBCentralManager:\n"
        "    @classmethod\n"
        "    def alloc(cls):\n"
        "        return cls()\n"
        "    def initWithDelegate_queue_(self, delegate, queue):\n"
        "        delegate.centralManagerDidUpdateState_(_Central())\n"
        "        return self\n",
        encoding="utf-8",
    )
    (stub_dir / "bleak.py").write_text(
        "class _Device:\n"
        "    address = '00:00:00:00:00:00'\n"
        "    name = None\n"
        "    rssi = 0\n"
        "class BleakScanner:\n"
        "    @staticmethod\n"
        "    async def discover(timeout):\n"
        f"        return [_Device()] * {device_count}\n",
        encoding="utf-8",
    )
    return stub_dir


def _run_script(tmp_path: Path, stub_dir: Path | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    # Only the stub dir: the script imports nothing from this repo, so
    # a fixed PYTHONPATH keeps the run from depending on ambient env.
    env["PYTHONPATH"] = str(stub_dir or _make_unimportable_stubs(tmp_path))
    return subprocess.run(
        [sys.executable, str(_SCRIPT)],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=str(_SCRIPT.parent.parent),
        env=env,
    )


# ---------- structural: the script is parseable and self-consistent ----------


def test_script_file_parses():
    """The first syntax check this file has ever had from the suite."""
    assert _parse_script() is not None


def test_every_verdict_call_uses_a_documented_label():
    """Structural check (TESTING_POLICY rule 8): the script's contract
    is the single verdict label it prints, so a call site inventing a
    sixth label — or a documented one going dead — should fail loudly
    rather than quietly diverge from the docstring that lists them.
    """
    used = set()
    for node in ast.walk(_parse_script()):
        if not isinstance(node, ast.Call):
            continue
        if getattr(node.func, "id", None) != "verdict":
            continue
        assert node.args, f"verdict() called with no label at line {node.lineno}"
        label = node.args[0]
        assert isinstance(label, ast.Constant) and isinstance(label.value, str), (
            f"verdict() label at line {node.lineno} is not a string literal"
        )
        used.add(label.value)

    assert used == _DOCUMENTED_VERDICTS


# ---------- behavioral: honest absence, never a fabricated empty result ----------


def test_missing_dependencies_report_api_unavailable_not_zero_results(tmp_path):
    """TESTING_POLICY rule 9 / AGENTS rule 7: with the Bluetooth
    dependencies unimportable, the script must say it could not
    determine Bluetooth state — never report the run as having
    completed and simply found nothing nearby. That distinction is the
    stated reason this script exists (docs/CAPABILITIES_MATRIX.md
    line 23), so it is worth an assertion rather than a comment.
    """
    proc = _run_script(tmp_path)
    output = proc.stdout + proc.stderr

    assert "=== VERDICT: API_UNAVAILABLE_OR_ERROR ===" in output
    assert "OPERATIONAL_ZERO_RESULTS" not in output
    assert "OPERATIONAL_SCAN_OK" not in output


def test_exactly_one_verdict_line_is_printed(tmp_path):
    """The docstring's "prints exactly one final verdict line" is the
    whole output contract — two verdicts, or none, would make the
    result unreadable.
    """
    proc = _run_script(tmp_path)
    output = proc.stdout + proc.stderr

    verdict_lines = [line for line in output.splitlines() if line.startswith("=== VERDICT:")]
    assert len(verdict_lines) == 1, f"expected one verdict line, got {verdict_lines}"


def test_script_never_reaches_bluetooth_when_dependencies_are_missing(tmp_path):
    """Proves the guard above the CBCentralManager construction is what
    stopped the run — if the stubs had failed to shadow a real PyObjC,
    the script would have printed its pre-scan progress lines instead.
    """
    proc = _run_script(tmp_path)
    output = proc.stdout + proc.stderr

    assert "Attempting an 8-second live BLE scan" not in output
    assert "CBCentralManager.state = " not in output


# ---------- behavioral: the exit status agrees with the verdict ----------


def test_missing_dependencies_exit_nonzero(tmp_path):
    """A run that could not even determine Bluetooth state must not
    exit 0 — a caller reading only the status would take it for a
    working scan (AGENTS rule 7).
    """
    proc = _run_script(tmp_path)

    assert "=== VERDICT: API_UNAVAILABLE_OR_ERROR ===" in proc.stdout
    assert proc.returncode == 1


def test_every_verdict_exits_zero_only_when_operational(tmp_path):
    """Drives each documented verdict through the fakes and pins its
    exit status: 0 for the two OPERATIONAL_* outcomes, 1 for the rest.
    Before this, verdict() ended in an unconditional sys.exit(0), so
    PERMISSION_DENIED and POWERED_OFF exited exactly like a good scan.
    """
    # (CBCentralManager state, devices found) -> (verdict, exit status)
    cases = {
        (3, 0): ("PERMISSION_DENIED", 1),
        (4, 0): ("POWERED_OFF", 1),
        (2, 0): ("API_UNAVAILABLE_OR_ERROR", 1),
        (0, 0): ("API_UNAVAILABLE_OR_ERROR", 1),
        (5, 0): ("OPERATIONAL_ZERO_RESULTS", 0),
        (5, 2): ("OPERATIONAL_SCAN_OK", 0),
    }
    assert {label for label, _ in cases.values()} == _DOCUMENTED_VERDICTS

    for (state, devices), (label, status) in cases.items():
        proc = _run_script(tmp_path, _make_fake_bluetooth(tmp_path, state, devices))
        verdict_lines = [line for line in proc.stdout.splitlines() if line.startswith("=== VERDICT:")]

        assert _FAKE_MARKER in proc.stdout, f"fakes not used for state={state}: {proc.stderr}"
        assert verdict_lines == [f"=== VERDICT: {label} ==="], (state, devices, verdict_lines, proc.stderr)
        assert proc.returncode == status, (label, proc.returncode)
