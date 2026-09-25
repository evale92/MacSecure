"""tests/test_agent_toolchain.py — Phase 46
("Dependency & Security Tool Maintenance").

Acceptance criterion under test (verbatim, from

    "Secure can identify and analyze representative dependency/tool
    maintenance situations and produce a verified proposal/change
    request without silently altering the live environment."

Every scenario here is SIMULATED, as the governing text asks: health
results are injected rather than collected from real tools, the model
backend's reachability is injected rather than probed, and the
requirements file is a fixture in `tmp_path`. **No test in this file
installs, updates, or removes anything, and none makes a network
call.** The strongest tests are the ones proving that is structurally
true rather than merely observed.
"""

from __future__ import annotations

import ast
from pathlib import Path

from secure.agent.classify import CLASS_DEPENDENCY_CHANGE, CLASS_SYSTEM_CHANGE
from secure.agent.toolchain import (
    ALL_SITUATION_KINDS,
    SITUATION_DEGRADED,
    SITUATION_ERROR,
    SITUATION_MODEL_BACKEND_UNREACHABLE,
    SITUATION_UNAVAILABLE,
    SITUATION_UNPINNED_DEPENDENCY,
    SITUATION_VERSION_DRIFT,
    MaintenanceSituation,
    analyze,
    describe,
    propose_maintenance,
    survey,
    survey_dependencies,
    survey_integrations,
    survey_model_backend,
)
from secure.config import AppConfig, default_config
from secure.integrations.base import (
    STATUS_DEGRADED,
    STATUS_ERROR,
    STATUS_OK,
    STATUS_UNAVAILABLE,
    IntegrationHealth,
)
from secure.storage.database import Database
from secure.storage.models import latest_tool_version, list_tool_versions


def _cfg(tmp_path: Path) -> AppConfig:
    cfg = default_config()
    cfg.app_dir = str(tmp_path / "appdir")
    return cfg


def _health(status=STATUS_OK, *, name="osquery", version=None, detail="detail"):
    return [(name, IntegrationHealth(status=status, detail=detail, collected_at="now", tool_version=version))]


# =====================================================================
# Representative situations, simulated
# =====================================================================


def test_an_unavailable_integration_is_a_maintenance_situation(tmp_path: Path):
    with Database(tmp_path / "s.db") as db:
        situations = survey_integrations(db.conn, _cfg(tmp_path), health=_health(STATUS_UNAVAILABLE))
    assert [s.kind for s in situations] == [SITUATION_UNAVAILABLE]
    assert situations[0].component == "osquery"


def test_an_erroring_integration_is_a_maintenance_situation(tmp_path: Path):
    with Database(tmp_path / "s.db") as db:
        situations = survey_integrations(db.conn, _cfg(tmp_path), health=_health(STATUS_ERROR, version="1.2.3"))
    assert [s.kind for s in situations] == [SITUATION_ERROR]
    assert situations[0].observed_version == "1.2.3"


def test_a_degraded_integration_is_a_maintenance_situation(tmp_path: Path):
    with Database(tmp_path / "s.db") as db:
        situations = survey_integrations(db.conn, _cfg(tmp_path), health=_health(STATUS_DEGRADED))
    assert [s.kind for s in situations] == [SITUATION_DEGRADED]


def test_a_healthy_integration_produces_no_situation(tmp_path: Path):
    with Database(tmp_path / "s.db") as db:
        situations = survey_integrations(db.conn, _cfg(tmp_path), health=_health(STATUS_OK, version="1.0.0"))
    assert situations == []


# ---------- version drift ----------


def test_a_first_observation_is_not_drift(tmp_path: Path):
    """Seeing a version for the first time is not a change."""
    with Database(tmp_path / "s.db") as db:
        situations = survey_integrations(db.conn, _cfg(tmp_path), health=_health(version="1.0.0"))
        assert situations == []
        assert latest_tool_version(db.conn, "osquery").tool_version == "1.0.0"


def test_a_changed_version_is_reported_as_drift(tmp_path: Path):
    """The simulated update scenario: a tool that was healthy at one
    version is now healthy at another. Health alone would never notice."""
    cfg = _cfg(tmp_path)
    with Database(tmp_path / "s.db") as db:
        survey_integrations(db.conn, cfg, health=_health(version="1.0.0"))
        situations = survey_integrations(db.conn, cfg, health=_health(version="2.0.0"))
    assert [s.kind for s in situations] == [SITUATION_VERSION_DRIFT]
    assert situations[0].previous_version == "1.0.0"
    assert situations[0].observed_version == "2.0.0"


def test_drift_is_detected_even_when_the_tool_is_perfectly_healthy(tmp_path: Path):
    cfg = _cfg(tmp_path)
    with Database(tmp_path / "s.db") as db:
        survey_integrations(db.conn, cfg, health=_health(STATUS_OK, version="1.0.0"))
        situations = survey_integrations(db.conn, cfg, health=_health(STATUS_OK, version="1.0.1"))
    assert situations and situations[0].kind == SITUATION_VERSION_DRIFT


def test_the_same_version_twice_is_not_drift(tmp_path: Path):
    cfg = _cfg(tmp_path)
    with Database(tmp_path / "s.db") as db:
        survey_integrations(db.conn, cfg, health=_health(version="1.0.0"))
        situations = survey_integrations(db.conn, cfg, health=_health(version="1.0.0"))
    assert situations == []


def test_every_observed_version_is_retained_as_history(tmp_path: Path):
    cfg = _cfg(tmp_path)
    with Database(tmp_path / "s.db") as db:
        survey_integrations(db.conn, cfg, health=_health(version="1.0.0"))
        survey_integrations(db.conn, cfg, health=_health(version="2.0.0"))
        history = list_tool_versions(db.conn, "osquery")
    assert [h.tool_version for h in history] == ["1.0.0", "2.0.0"]


def test_a_tool_with_no_version_string_records_nothing_rather_than_an_empty_version(tmp_path: Path):
    """"We have never seen a version" and "the version is blank" must
    stay distinguishable."""
    with Database(tmp_path / "s.db") as db:
        survey_integrations(db.conn, _cfg(tmp_path), health=_health(version=None))
        assert latest_tool_version(db.conn, "osquery") is None


# ---------- dependencies ----------


def test_an_unpinned_dependency_is_a_maintenance_situation(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text("# a comment\nbleak>=3.0.2\nsomepackage\n")
    situations = survey_dependencies(requirements_path=req)
    assert [s.kind for s in situations] == [SITUATION_UNPINNED_DEPENDENCY]
    assert situations[0].component == "somepackage"


def test_a_pinned_dependency_produces_no_situation(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text("bleak>=3.0.2\npyobjc-framework-CoreBluetooth>=12.2.2\n")
    assert survey_dependencies(requirements_path=req) == []


def test_comments_and_blank_lines_are_ignored(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text("# just a comment\n\n   \n# another\n")
    assert survey_dependencies(requirements_path=req) == []


def test_a_missing_requirements_file_is_not_an_error(tmp_path: Path):
    assert survey_dependencies(requirements_path=tmp_path / "nope.txt") == []


def test_this_projects_own_requirements_are_all_pinned():
    """A real check against the live manifest, not a fixture."""
    from secure.agent.worktree import project_root

    assert survey_dependencies(requirements_path=project_root() / "requirements.txt") == []


# ---------- model backend ----------


def test_an_unreachable_configured_backend_is_a_system_change_situation(tmp_path: Path):
    cfg = _cfg(tmp_path)
    cfg.ollama_host = "http://127.0.0.1:11434"
    situations = survey_model_backend(cfg, reachable=False)
    assert [s.kind for s in situations] == [SITUATION_MODEL_BACKEND_UNREACHABLE]
    assert situations[0].classification == CLASS_SYSTEM_CHANGE


def test_an_unconfigured_backend_is_not_a_situation(tmp_path: Path):
    cfg = _cfg(tmp_path)
    cfg.ollama_host = ""
    assert survey_model_backend(cfg, reachable=False) == []


def test_reachability_is_never_guessed(tmp_path: Path):
    """When nobody told this function whether the backend answers, it
    reports nothing rather than assuming — and it certainly does not
    make a network call to find out."""
    cfg = _cfg(tmp_path)
    cfg.ollama_host = "http://127.0.0.1:11434"
    assert survey_model_backend(cfg, reachable=None) == []


# =====================================================================
# Classification and analysis
# =====================================================================


def test_every_situation_kind_requires_approval():
    for kind in ALL_SITUATION_KINDS:
        situation = MaintenanceSituation(kind=kind, component="x", summary="s", evidence="e")
        assert situation.requires_approval is True
        assert situation.classification in (CLASS_DEPENDENCY_CHANGE, CLASS_SYSTEM_CHANGE)


def test_every_situation_kind_has_a_real_analysis():
    for kind in ALL_SITUATION_KINDS:
        situation = MaintenanceSituation(
            kind=kind, component="x", summary="s", evidence="e",
            observed_version="2", previous_version="1",
        )
        text = analyze(situation)
        assert "No analysis is defined" not in text
        assert "Secure has NOT changed anything" in text


def test_the_analysis_never_claims_to_know_what_version_is_current():
    """Secure has no way to know that without a network lookup it does
    not perform, so it must not imply otherwise."""
    situation = MaintenanceSituation(
        kind=SITUATION_VERSION_DRIFT, component="osquery", summary="s", evidence="e",
        observed_version="2.0.0", previous_version="1.0.0",
    )
    text = analyze(situation).lower()
    for phrase in ("latest version", "up to date", "outdated", "newest"):
        assert phrase not in text


def test_describe_says_nothing_was_changed(tmp_path: Path):
    situations = [MaintenanceSituation(SITUATION_UNAVAILABLE, "osquery", "s", "e")]
    assert "Secure has changed nothing" in describe(situations)


def test_describe_handles_an_empty_survey():
    assert "No toolchain maintenance situations" in describe([])


# =====================================================================
# Proposals — and the live environment stays untouched
# =====================================================================


def test_a_situation_becomes_a_pending_approval_gated_change_request(tmp_path: Path):
    cfg = _cfg(tmp_path)
    situation = MaintenanceSituation(SITUATION_UNAVAILABLE, "osquery", "osquery is unavailable", "not found")
    with Database(tmp_path / "s.db") as db:
        cr = propose_maintenance(db.conn, cfg, situation)
    assert cr.status == "pending"
    assert cr.classification == CLASS_DEPENDENCY_CHANGE


def test_a_backend_situation_is_proposed_as_a_system_change(tmp_path: Path):
    cfg = _cfg(tmp_path)
    situation = MaintenanceSituation(SITUATION_MODEL_BACKEND_UNREACHABLE, "ollama", "s", "e")
    with Database(tmp_path / "s.db") as db:
        cr = propose_maintenance(db.conn, cfg, situation)
    assert cr.classification == CLASS_SYSTEM_CHANGE


def test_the_proposal_states_that_approving_it_installs_nothing(tmp_path: Path):
    cfg = _cfg(tmp_path)
    situation = MaintenanceSituation(SITUATION_UNAVAILABLE, "osquery", "s", "e")
    with Database(tmp_path / "s.db") as db:
        cr = propose_maintenance(db.conn, cfg, situation)
    assert "does not install, update, or remove anything" in cr.risks
    assert "You perform the operation yourself" in cr.risks


def test_the_proposal_credits_no_model_because_none_was_involved(tmp_path: Path):
    cfg = _cfg(tmp_path)
    situation = MaintenanceSituation(SITUATION_VERSION_DRIFT, "osquery", "s", "e",
                                     observed_version="2", previous_version="1")
    with Database(tmp_path / "s.db") as db:
        cr = propose_maintenance(db.conn, cfg, situation)
    assert "no model was involved" in cr.model_a_opinion
    assert "no model was involved" in cr.model_b_opinion


def test_proposing_does_not_modify_the_requirements_file(tmp_path: Path):
    cfg = _cfg(tmp_path)
    from secure.agent.worktree import project_root

    req = project_root() / "requirements.txt"
    before = req.read_bytes()
    situation = MaintenanceSituation(SITUATION_UNPINNED_DEPENDENCY, "somepkg", "s", "e")
    with Database(tmp_path / "s.db") as db:
        propose_maintenance(db.conn, cfg, situation)
    assert req.read_bytes() == before


def test_a_full_survey_combines_every_source(tmp_path: Path):
    cfg = _cfg(tmp_path)
    cfg.ollama_host = "http://127.0.0.1:11434"
    req = tmp_path / "requirements.txt"
    req.write_text("unpinnedpkg\n")
    with Database(tmp_path / "s.db") as db:
        situations = survey(
            db.conn, cfg, health=_health(STATUS_UNAVAILABLE),
            model_reachable=False, requirements_path=req,
        )
    kinds = {s.kind for s in situations}
    assert kinds == {SITUATION_UNAVAILABLE, SITUATION_MODEL_BACKEND_UNREACHABLE, SITUATION_UNPINNED_DEPENDENCY}


# =====================================================================
# There is no update path — enforced by absence
# =====================================================================


_SOURCE = Path(__file__).resolve().parents[1] / "secure" / "agent" / "toolchain.py"


def _non_docstring_literals(tree):
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc:
                docstrings.add(doc)
    return [
        n.value for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value not in docstrings
    ]


def test_the_module_never_runs_a_subprocess():
    """An update path that exists is an update path a bug can reach —
    and the thing it would reach into is this machine's security
    stack."""
    tree = ast.parse(_SOURCE.read_text(encoding="utf-8"), filename=str(_SOURCE))
    offending = [
        f"line {n.lineno}: .{n.attr}" for n in ast.walk(tree)
        if isinstance(n, ast.Attribute) and n.attr in ("run", "Popen", "check_output", "check_call", "system")
    ]
    assert offending == []


def test_the_module_names_no_package_manager_command():
    """Checks for a COMMAND SHAPE, not for the word "install".

    The first version of this test banned the substring "install"
    outright and failed — because this module's proposal text says, in
    prose, that approving it "does not install, update, or remove
    anything." That sentence is the honest documentation this phase
    requires, and banning the word would have meant deleting it. Same
    false-positive class as Phase 29's launchctl check, which is why
    that one is argv-shaped too.

    What actually matters is that no literal is a package-manager
    binary used as an argv token, and no literal contains a
    package-manager command phrase.
    """
    tree = ast.parse(_SOURCE.read_text(encoding="utf-8"), filename=str(_SOURCE))
    literals = _non_docstring_literals(tree)

    binaries = {"pip", "pip3", "brew", "npm", "apt", "apt-get", "port", "conda"}
    argv_tokens = [lit for lit in literals if lit.strip() in binaries]
    assert argv_tokens == [], f"package-manager binary used as an argv token: {argv_tokens}"

    command_phrases = [
        f"{binary} {verb}"
        for binary in sorted(binaries)
        for verb in ("install", "uninstall", "upgrade", "update", "remove")
    ]
    offending = [
        (lit[:60], phrase) for lit in literals for phrase in command_phrases if phrase in lit
    ]
    assert offending == [], f"package-manager command phrase in a literal: {offending}"


def test_the_module_never_writes_a_file():
    tree = ast.parse(_SOURCE.read_text(encoding="utf-8"), filename=str(_SOURCE))
    offending = [
        f"line {n.lineno}: .{n.attr}" for n in ast.walk(tree)
        if isinstance(n, ast.Attribute) and n.attr in ("write_text", "write_bytes", "unlink", "rmtree")
    ]
    assert offending == []


def test_the_module_makes_no_network_call():
    tree = ast.parse(_SOURCE.read_text(encoding="utf-8"), filename=str(_SOURCE))
    banned_imports = {"urllib", "requests", "http", "socket", "httpx", "urllib3"}
    offending = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            offending += [a.name for a in node.names if a.name.split(".")[0] in banned_imports]
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module.split(".")[0] in banned_imports:
                offending.append(node.module)
    assert offending == []


def test_the_module_never_approves_anything():
    tree = ast.parse(_SOURCE.read_text(encoding="utf-8"), filename=str(_SOURCE))
    banned = {"approve_change", "reject_change"}
    offending = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and any(a.name in banned for a in node.names):
            offending.append(f"line {node.lineno}")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in banned:
            offending.append(f"line {node.lineno}")
    assert offending == []
