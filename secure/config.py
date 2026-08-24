"""
config.py — where the app's settings live and how they're loaded/saved.

Design choice (beginner-friendly on purpose):
    Settings are a plain Python dataclass, stored on disk as a single
    JSON file. No external libraries, no magic. If you can read JSON,
    you can read this app's configuration.

Where the config file lives:
    ~/.secure/config.json

    We use a dotfile in the user's home directory (a common convention
    for command-line tools) rather than the project folder, so the app
    behaves the same no matter where the source code is checked out.

Multi-device model:
    This same project folder (the "template") is meant to be copied
    onto more than one machine — for example your always-on Mac mini
    and your MacBook. Nothing about the *code* changes between
    machines. What differs is each machine's own ~/.secure/config.json,
    which is never committed to git and never synced automatically.

    Two fields exist for this: `device_name` (auto-detected from the
    OS, e.g. "ericks-Mac-mini" or "MacBook-Pro-2") and `device_role`,
    which you set yourself — typically "server" for a machine that's
    meant to stay on all the time, and "workstation" for one that
    isn't. Nothing currently *acts* on device_role — there is no
    remote-control or cross-device orchestration yet. It's just a
    label each instance carries about itself, so that future features
    (like a server instance being allowed to coordinate workstation
    instances over a trusted, authenticated channel) have something
    to key off of instead of being bolted on later as a rewrite.

What's in this file:
    - AppConfig: the dataclass describing every setting the app has.
    - default_config(): builds an AppConfig with sane defaults.
    - load_config(): reads config.json, falling back to defaults if it
      doesn't exist yet (and creates it, so the file is self-healing).
    - save_config(): writes an AppConfig back to disk as JSON.
"""

from __future__ import annotations

import json
import platform
from dataclasses import asdict, dataclass, field
from pathlib import Path

from secure.permissions import harden_dir, harden_file

# Everything the app writes (config, database, logs) lives under this
# directory by default. Keeping it in one place makes the app easy to
# fully uninstall later: delete this folder and it's gone.
DEFAULT_APP_DIR = Path.home() / ".secure"

# Roles a device can declare for itself. This is descriptive only for
# now (see the module docstring) — nothing branches on it yet.
DEVICE_ROLES = ("server", "workstation")


class ConfigError(RuntimeError):
    """Raised when ~/.secure/config.json exists but cannot be used —
    e.g. it's not valid JSON (a previous write was interrupted: the
    disk filled up, the process was killed mid-save) or it's valid JSON
    but not a JSON object.

    Phase 29 Stage 7 hardening: before this existed, a corrupted
    config.json crashed every single CLI command with a raw
    json.JSONDecodeError traceback and no indication of what to do
    about it. Deliberately NOT auto-repaired, backed up, or deleted —
    consistent with this project's own "no autonomous remediation, no
    destructive filesystem operations" invariants (see
    docs/THREAT_MODEL.md): the broken file might be worth inspecting by
    hand, so the fix here is always a clear, actionable message, never
    a silent overwrite of something the operator didn't ask to change.
    """


def _detect_device_name() -> str:
    """Best-effort local hostname, used as a default only.

    This never talks to the network — `platform.node()` just reads the
    hostname the OS already knows about itself.
    """
    return platform.node() or "unknown-device"


@dataclass
class AppConfig:
    """All configurable settings for the app, in one place.

    Add new settings here as the project grows. Because this is a
    dataclass, load_config()/save_config() automatically pick up any
    new fields you add — you don't need to touch the JSON parsing.
    """

    # Directory that holds config.json, the SQLite database, and logs.
    app_dir: str = str(DEFAULT_APP_DIR)

    # Path to the SQLite database file (relative to app_dir unless
    # you give it an absolute path).
    database_filename: str = "secure.db"

    # Path to the log file (relative to app_dir unless absolute).
    log_filename: str = "secure.log"

    # Standard logging level name: DEBUG, INFO, WARNING, ERROR.
    log_level: str = "INFO"

    # Directory holding user-provided YARA-X ruleset files (*.yar/*.yara),
    # relative to app_dir unless given an absolute path (Phase 16 —
    # see secure/integrations/yarax/). Self-healing: an empty/missing
    # directory just means zero rulesets are currently configured, not
    # an error — see yarax/rulesets.py.
    yara_rules_dir: str = "yara_rules"

    # Directory holding user-provided Sigma rule files (*.yml/*.yaml),
    # relative to app_dir unless given an absolute path (Phase 17 —
    # see secure/integrations/sigma/). Same self-healing convention as
    # yara_rules_dir: empty/missing just means zero rules configured.
    sigma_rules_dir: str = "sigma_rules"

    # Path to Suricata's own EVE JSON log file (Phase 18 — see
    # secure/integrations/suricata/). Unlike yara_rules_dir/
    # sigma_rules_dir, this is NOT resolved relative to app_dir by
    # default — Suricata's own install location varies a lot (Homebrew,
    # a Linux package, a custom build) and Secure never installs or
    # configures Suricata itself, only reads whatever log path the user
    # points it at. Empty string means "not configured yet" — the same
    # self-healing "absence is normal, not an error" convention as
    # every other optional integration field, surfaced as
    # STATUS_UNAVAILABLE (never a crash) until set.
    suricata_eve_log_path: str = ""

    # Directory holding Zeek's own JSON log output (conn.log, dns.log,
    # ssl.log, http.log — Phase 19, see secure/integrations/zeek/).
    # Same "NOT resolved relative to app_dir" convention as
    # suricata_eve_log_path, for the same reason: Zeek's own install/
    # spool location varies a lot (Homebrew's /opt/homebrew/var/log/
    # zeek/current, a Linux package, a custom deployment) and Secure
    # never installs, configures, or manages Zeek itself, only reads
    # whatever log directory the user points it at. Empty string means
    # "not configured yet", surfaced as STATUS_UNAVAILABLE, never a
    # crash — same self-healing convention as every other optional
    # integration field.
    zeek_log_dir: str = ""

    # Directory holding local threat-intelligence feed files (Phase 20
    # — see secure/threatintel/providers/local_feed.py): plain text
    # lists named `ip_feed.txt` / `domain_feed.txt` / `hash_feed.txt`,
    # one indicator per line, `value,category,severity` (category/
    # severity optional). Resolved relative to app_dir, same convention
    # as yara_rules_dir/sigma_rules_dir — this is Secure's OWN data
    # directory, unlike suricata_eve_log_path/zeek_log_dir which point
    # at another program's own install location. Empty/missing means
    # zero local feed entries configured, never an error.
    threat_intel_local_feed_dir: str = "threat_intel_feeds"

    # Optional VirusTotal API key (Phase 20 — see
    # secure/threatintel/providers/virustotal.py). Empty string means
    # "not configured" — surfaced as STATUS_UNAVAILABLE, never a crash,
    # the same self-healing convention as every other optional
    # integration field. Stored in plain ~/.secure/config.json, same as
    # every other setting in this file (see this module's own docstring
    # on the multi-device model: config.json is never committed or
    # synced automatically) — no worse than this app's existing
    # security model, but worth knowing if you populate this field.
    virustotal_api_key: str = ""

    # Default cache lifetime for a threat-intelligence lookup when a
    # provider's own response doesn't specify one (Phase 20's own
    # "expiration/TTL" requirement) — see secure/threatintel/enrich.py.
    threat_intel_cache_ttl_hours: float = 24.0

    # Path to the `velociraptor` binary (Phase 24 — see secure/dfir/).
    # Empty string means "use whatever `velociraptor` resolves to on
    # PATH" (mirrors suricata_eve_log_path/zeek_log_dir's own "Secure
    # never installs or configures this tool itself" convention) — NOT
    # resolved relative to app_dir, since Velociraptor's own install
    # location varies (Homebrew, a manual binary download, a custom
    # build) and has nothing to do with Secure's own data directory.
    # An unreachable/missing binary surfaces as STATUS_UNAVAILABLE, same
    # self-healing "absence is normal, not an error" convention as every
    # other optional integration field — never a crash.
    velociraptor_binary_path: str = ""

    # The ONLY artifact names `secure dfir collect` will ever run —
    # deliberately empty by default, meaning NO artifact is collectible
    # until an operator explicitly adds names here. This is the concrete
    # safety rail behind the instruction's "do not trigger broad
    # forensic collection" and "narrowly scoped... based on an
    # investigation": Secure never ships a built-in catalog of "useful"
    # Velociraptor artifacts to run, and never expands this list on its
    # own — see secure/dfir/collector.py's own enforcement of this field
    # BEFORE any subprocess is ever started.
    dfir_artifact_allowlist: "list[str]" = field(default_factory=list)

    # Ollama's local HTTP API base URL (Phase 28 — see secure/ai/
    # providers/ollama.py). Empty string means "not configured" —
    # surfaced as STATUS_UNAVAILABLE, never a crash, the same
    # empty-value-gate discipline virustotal_api_key already established:
    # nothing here ever calls out to a local model daemon unless the
    # operator has explicitly set this field. When set, the typical
    # value is "http://127.0.0.1:11434" (Ollama's own default bind
    # address) — Secure never starts, installs, or manages Ollama
    # itself, only talks to whatever instance is already running there.
    ollama_host: str = ""

    # Which model Ollama should run a request against (e.g. "llama3.1").
    # Only meaningful when ollama_host is set.
    ollama_model: str = "llama3.1"

    ollama_timeout_seconds: float = 60.0

    # A second, generic local model backend speaking the OpenAI
    # chat-completions API shape (Phase 28 — see secure/ai/providers/
    # openai_compatible.py) — covers LM Studio, llama.cpp's own server,
    # MLX-compatible servers, vLLM, text-generation-webui, and anything
    # else exposing a local /v1/chat/completions endpoint, with one
    # implementation. Same empty-means-unconfigured gate as ollama_host.
    # Typical value: "http://127.0.0.1:1234/v1" (LM Studio's default).
    local_llm_host: str = ""

    local_llm_model: str = ""

    # Most local servers ignore this or accept any placeholder value —
    # kept optional (empty is fine) rather than required, since a local,
    # non-network-exposed server usually has no real auth in front of it.
    local_llm_api_key: str = ""

    local_llm_timeout_seconds: float = 60.0

    # Where an AI-proposed change request's notification email goes
    # (Phase 28 — see secure/ai/changes/notify.py). Defaults to the
    # operator's own address exactly as given in this phase's own
    # governing instruction. This is only ever a destination, never a
    # trigger — email delivery (or its failure) never gates change-request
    # creation and is never treated as approval.
    ai_notify_email: str = "evale92@gmail.com"

    # Outbound SMTP relay settings for change-request notifications.
    # `smtp_host` empty means "not configured" — the same gate-before-
    # any-I/O discipline as ollama_host/local_llm_host/virustotal_api_key:
    # a PENDING change request is still created and still requires
    # `secure ai changes approve` either way; only the notification email
    # itself is skipped (and honestly reported as such) until an operator
    # fills these in — e.g. an app-password-authenticated Gmail relay at
    # smtp_host="smtp.gmail.com", smtp_port=587, smtp_use_tls=True.
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = True
    smtp_from_addr: str = ""

    # This machine's hostname, auto-detected the first time `secure
    # init` runs. Purely informational today — see module docstring.
    device_name: str = field(default_factory=_detect_device_name)

    # "server" (always-on, e.g. the Mac mini) or "workstation" (comes
    # and goes, e.g. a MacBook). You set this explicitly, usually via
    # `secure init --role server`, because the app has no reliable way
    # to guess it on its own.
    device_role: str = "workstation"

    # --- Phase 30: Performance & Diagnostics -------------------------
    # Ordinary, always-on behavior — no enable/disable flag exists here
    # on purpose (an earlier draft of this phase gated it behind a
    # "Developer Mode" toggle; the approved design removed that: this
    # is normal diagnostics, not a special mode). See secure/diagnostics/
    # and docs/PERFORMANCE.md.

    # Comma-separated, case-sensitive substrings matched against running
    # processes' command names for `secure diagnostics tools`'s generic
    # external-development-tool resource aggregate (Phase 30). Deliberately
    # generic — not hardcoded to "Claude" in code — so other tools can be
    # added here later without a code change. Reports only aggregate
    # process count/CPU%/RSS; never inspects a matched process's
    # arguments, files, network activity, or private contents.
    dev_tool_process_patterns: str = "Claude"

    # Configurable performance-diagnostic thresholds (Phase 30). These
    # produce plain factual warning strings ("Secure's RSS was 612MB,
    # above the configured 500MB budget") — never security alerts, never
    # fed into severity/anomaly scoring/correlation/explainability (see
    # secure/diagnostics/budgets.py's own module docstring).
    perf_budget_secure_max_rss_mb: float = 500.0
    perf_budget_scan_max_seconds: float = 60.0
    perf_budget_min_free_disk_gb: float = 5.0
    perf_budget_db_growth_warn_mb_per_run: float = 50.0

    # --- Phase 31: Agent Foundation ----------------------------------
    # Supervised, human-approved autonomous repair. There is
    # deliberately NO master enable/disable flag here — the same reason
    # Phase 30 has none: this is not a "mode," it's a normal command
    # (`secure agent run`) that only ever does anything when a human
    # types it. What's gated instead is WHAT it's allowed to touch and
    # HOW FAR it can go on its own — see each field below. Nothing in
    # this section is read by anything below the interfaces layer; see
    # secure/agent/ and docs/AGENT_FOUNDATION.md.

    # Which external agent tool `secure agent run` invokes. Phase 31
    # supports exactly one value — "mini-swe-agent" — on purpose (the
    # governing instruction: "Do not add Aider or OpenHands during
    # Phase 31"). The field exists (rather than hardcoding the name in
    # code) only so a later phase can add a second tool without another
    # schema/config migration.
    agent_tool: str = "mini-swe-agent"

    # The exact command used to invoke the tool's CLI. Empty means
    # "not configured" — the same empty-gate discipline as
    # ollama_host/velociraptor_binary_path: secure/agent/runner.py
    # reports STATUS_UNAVAILABLE and runs nothing until this is set.
    # Typical value: "mini" (if installed on PATH) or an absolute path.
    agent_tool_binary: str = ""

    # Which trigger kinds `secure agent run` will act on. Phase 31's
    # governing instruction restricts this to deterministic test/
    # validation failures only — never a security finding. The default
    # is deliberately the full Phase-31-supported set, not empty,
    # because (unlike dfir_artifact_allowlist's "nothing collectible
    # until an operator opts in") a failing test is not a sensitive
    # capability to gate behind an empty default; the boundary that
    # matters here is TRIGGER KIND, not opt-in/opt-out.
    agent_allowed_trigger_kinds: "list[str]" = field(
        default_factory=lambda: ["pytest_failure", "validate_scenario_failure", "detect_rule_test_failure"]
    )

    # Repo-relative path prefixes the agent may never be pointed at or
    # allowed to change. A produced diff touching any of these paths is
    # automatically rejected before a change request is ever created —
    # see secure/agent/changes.py's own enforcement. Deliberately
    # includes the deterministic authorities this whole phase relies on
    # (validate/, ai/verify, ai/changes, config.py, database.py's schema)
    # so a repair can never rewrite the referee that grades it.
    agent_path_denylist: "list[str]" = field(
        default_factory=lambda: [
            "secure/validate/", "secure/ai/verify/", "secure/ai/changes/",
            "secure/agent/", "secure/config.py", "secure/storage/database.py",
            ".git/", "docs/",
        ]
    )

    # Bounded retries (governing instruction: "use bounded retries and
    # stop on architectural ambiguity"). One repair attempt = one `mini`
    # invocation + one verification pass; agent_max_attempts caps how
    # many attempts a single `secure agent run` will make against the
    # same trigger before giving up and recording status='error' with a
    # stop_reason, never looping indefinitely.
    agent_max_attempts: int = 2

    # Per-attempt bounds passed straight into the generated mini-swe-agent
    # config (agent.step_limit / agent.cost_limit) AND enforced again,
    # independently, as a wall-clock subprocess timeout by
    # secure/agent/runner.py itself — belt-and-suspenders, since a
    # local model backend has no meaningful dollar cost to bound by.
    agent_step_limit: int = 40
    agent_timeout_seconds: float = 900.0

    # Wall-clock timeout for the post-repair pytest/validate subprocess
    # calls (secure/agent/verify.py) — independent of agent_timeout_seconds,
    # which only bounds the tool's own run.
    agent_verify_timeout_seconds: float = 300.0

    def app_dir_path(self) -> Path:
        return Path(self.app_dir).expanduser()

    def database_path(self) -> Path:
        path = Path(self.database_filename)
        return path if path.is_absolute() else self.app_dir_path() / path

    def log_path(self) -> Path:
        path = Path(self.log_filename)
        return path if path.is_absolute() else self.app_dir_path() / path

    def yara_rules_dir_path(self) -> Path:
        path = Path(self.yara_rules_dir)
        return path if path.is_absolute() else self.app_dir_path() / path

    def sigma_rules_dir_path(self) -> Path:
        path = Path(self.sigma_rules_dir)
        return path if path.is_absolute() else self.app_dir_path() / path

    def threat_intel_local_feed_dir_path(self) -> Path:
        path = Path(self.threat_intel_local_feed_dir)
        return path if path.is_absolute() else self.app_dir_path() / path

    def suricata_eve_log_path_resolved(self) -> "Path | None":
        """None when unconfigured (the empty-string default) — callers
        treat that as STATUS_UNAVAILABLE, never a crash. When set, the
        path is expanded (`~`) but NOT resolved relative to app_dir,
        unlike every other *_dir_path() helper here — see
        suricata_eve_log_path's own field comment for why.
        """
        if not self.suricata_eve_log_path:
            return None
        return Path(self.suricata_eve_log_path).expanduser()

    def zeek_log_dir_resolved(self) -> "Path | None":
        """None when unconfigured (the empty-string default) — callers
        treat that as STATUS_UNAVAILABLE, never a crash. When set, the
        path is expanded (`~`) but NOT resolved relative to app_dir,
        same as suricata_eve_log_path_resolved() and for the same
        reason — see zeek_log_dir's own field comment.
        """
        if not self.zeek_log_dir:
            return None
        return Path(self.zeek_log_dir).expanduser()

    def velociraptor_binary_resolved(self) -> str:
        """The literal command to invoke: the configured path (expanded,
        NOT resolved relative to app_dir — see the field's own comment)
        when set, else the bare `"velociraptor"` command name so a
        subprocess call resolves it against PATH exactly the way every
        other external-tool integration in this app already does
        (suricata/_shell.py, osquery's own shell wrapper).
        """
        if not self.velociraptor_binary_path:
            return "velociraptor"
        return str(Path(self.velociraptor_binary_path).expanduser())


def default_config() -> AppConfig:
    """Return an AppConfig populated with default values."""
    return AppConfig()


def config_file_path(app_dir: Path | None = None) -> Path:
    """Where config.json lives, given an app_dir (defaults to ~/.secure)."""
    base = app_dir or DEFAULT_APP_DIR
    return base.expanduser() / "config.json"


def load_config(app_dir: Path | None = None) -> AppConfig:
    """Load settings from config.json, creating a default file if missing.

    This is intentionally forgiving: a fresh checkout of the project,
    or a machine that has never run the app before, should just work
    the first time you run any CLI command.
    """
    path = config_file_path(app_dir)

    if not path.exists():
        cfg = default_config()
        if app_dir is not None:
            cfg.app_dir = str(app_dir)
        save_config(cfg)
        return cfg

    with path.open("r", encoding="utf-8") as f:
        try:
            raw = json.load(f)
        except json.JSONDecodeError as exc:
            raise ConfigError(
                f"{path} exists but is not valid JSON ({exc}). This usually means a "
                "previous write was interrupted (e.g. the disk filled up, or the "
                "process was killed mid-save). Secure will not overwrite or delete "
                "this file automatically — either fix it by hand, restore it from a "
                "backup, or delete it yourself so a fresh default config.json can be "
                "created on the next run."
            ) from exc

    if not isinstance(raw, dict):
        raise ConfigError(
            f"{path} is valid JSON but not a JSON object (got {type(raw).__name__} "
            "instead) — this file may have been replaced by something else. Secure "
            "will not overwrite or delete it automatically; fix or remove it yourself."
        )

    # Start from defaults, then overlay whatever is in the file. This
    # means old config files still work even after you add new fields.
    cfg = default_config()
    for key, value in raw.items():
        if hasattr(cfg, key):
            setattr(cfg, key, value)
    return cfg


def save_config(cfg: AppConfig) -> Path:
    """Write an AppConfig to config.json, creating app_dir if needed.

    config.json can hold secrets (virustotal_api_key, local_llm_api_key,
    smtp_password) in plain text — see this module's own docstring and
    docs/THREAT_MODEL.md. Phase 29 Stage 4 hardens both the file and its
    parent directory to owner-only permissions every time this is
    called, best-effort (see secure/permissions.py).
    """
    path = config_file_path(Path(cfg.app_dir))
    path.parent.mkdir(parents=True, exist_ok=True)
    harden_dir(path.parent)

    with path.open("w", encoding="utf-8") as f:
        json.dump(asdict(cfg), f, indent=2, sort_keys=True)
        f.write("\n")

    harden_file(path)
    return path
