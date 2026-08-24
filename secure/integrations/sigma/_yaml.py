"""
integrations/sigma/_yaml.py — the ONLY place this integration touches
the `yaml` (PyYAML) library, lazily imported inside the one function
here, never at module load time. Mirrors secure/integrations/yarax/
_engine.py's own lazy-import seam for `yara_x` (itself modeled on
secure/bluetooth/ble/scanner.py's lazy `import bleak`) — the
established pattern in this codebase for an optional third-party
dependency: nothing that imports this module needs PyYAML installed to
be importable or unit-testable, and every test patches this one
function directly rather than needing the real library.

Unlike yara_x, PyYAML was actually available in the environment this
integration was built in, so — unlike Phase 16's yarax integration —
this module's behavior against a real install IS verified by this
project's own test suite (see tests/test_integrations_sigma.py),
loading real fixture Sigma rule YAML files end to end.
"""

from __future__ import annotations


def parse_yaml(text: str):
    """Parse one YAML document and return the resulting plain Python
    object (dict/list/scalar). Uses `yaml.safe_load` deliberately —
    Sigma rules are just data, never Python objects — so a malicious or
    malformed rule file can't smuggle in arbitrary object construction.
    Raises yaml.YAMLError (or a subclass) on malformed YAML; callers
    are responsible for catching that and reporting it as this one
    rule file's own load error, never aborting the rest of the batch.
    """
    import yaml  # noqa: PLC0415 - deliberately lazy, see module docstring

    return yaml.safe_load(text)
