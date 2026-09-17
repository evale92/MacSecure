"""
persistence/extra_locations.py — macOS persistence locations beyond
LaunchAgents/LaunchDaemons and login items, read directly from disk.

Like launch_items.py it reads files directly (a directory listing and
`plistlib`), except for the user's crontab, which only `crontab -l` can
read. It only reads; it never loads, unloads,
disables or deletes anything it lists.

**Scope, and why each location is here.** Every one is a documented
place third-party code (legitimate or malicious) runs from without being
a LaunchAgent/LaunchDaemon, and each is readable as a normal user:

    authorization_plugin  /Library/Security/SecurityAgentPlugins/*.bundle
                          loaded by the authorization system at login and
                          unlock prompts, with root privileges
    scripting_addition    /Library/ScriptingAdditions/*.osax and
                          ~/Library/ScriptingAdditions/*.osax
    kernel_extension      /Library/Extensions/*.kext (third-party kexts;
                          /System/Library/Extensions is SIP-protected and
                          Apple-signed, excluded for the same reason
                          launch_items.py excludes /System/Library)
    startup_item          /Library/StartupItems/* (legacy, still honoured
                          as a location malware writes to)
    periodic_script       /etc/daily.local, /etc/weekly.local,
                          /etc/monthly.local, run as root by periodic(8)
    emond_rule            /etc/emond.d/rules/*.plist (event monitor rules
                          that can run commands; absent on newer macOS)
    folder_action_script  ~/Library/Scripts/Folder Action Scripts/*
    ssh_rc                ~/.ssh/rc and /etc/ssh/sshrc, run by sshd for
                          every SSH login
    system_crontab        /etc/crontab (absent on a stock Mac)
    at_job                /usr/lib/cron/jobs/* (queued at(1) jobs)
    cron_job              one entry per job line of this user's crontab,
                          read with `/usr/bin/crontab -l` through
                          persistence/_shell.py — the only source here
                          that runs a subprocess
    hosts_entry           one entry per non-default mapping in /etc/hosts
                          (redirecting a domain here needs no resolver change)
    resolver_file         /etc/resolver/* (per-domain DNS overrides)
    manual_dns_server     DNS servers set by hand on a network service, read
                          with `/usr/sbin/networksetup -getdnsservers` — the
                          setting OSX/MaMi changed. DHCP-supplied servers are
                          deliberately not recorded: they change with every
                          network and would bury a real change in noise
    trusted_root          certificates given trust settings in the user and
                          admin domains (`/usr/bin/security dump-trust-settings`
                          and `-d`) — a root trusted by malware (OSX/MaMi) or
                          interception software. The system domain (Apple's
                          built-in roots) is deliberately not recorded
    ssh_authorized_key    one entry per key in ~/.ssh/authorized_keys and
                          authorized_keys2. Access persistence rather than
                          execution: a key someone added logs them back in
                          without a password. Identity is the key's SHA256
                          fingerprint, so a replaced key is a new entry.
    system_extension      `/usr/bin/systemextensionsctl list`: network,
                          endpoint-security and driver extensions, the
                          modern replacement for kexts and a favourite of
                          traffic-intercepting software
    configuration_profile `/usr/bin/profiles list` (this user's profiles)
                          plus `/usr/bin/profiles status -type enrollment`
                          (DEP/MDM enrollment), since a profile or an MDM
                          can install certificates, proxies and managed
                          settings without an app to show for it
    tcc_grant             allowed grants of the sensitive TCC services
                          (Full Disk Access, Screen Recording,
                          Accessibility, Input Monitoring, Camera,
                          Microphone, ...) from the system and user
                          TCC.db, read through storage/models/
                          macos_readonly.py. The user TCC.db needs Full
                          Disk Access; without it that location is
                          unavailable with the reason, never "no grants"

**Not covered, stated rather than hidden.** /usr/lib/cron/tabs (every
user's crontab) is root-only on every Mac, so only the scanning user's
own crontab is visible, and computer-level configuration profiles need
root to list (enrollment status does not, so an MDM is still seen). That is a privilege boundary this sensor never
crosses (no sudo), not a read that failed, so it is documented here
instead of being recorded as a scan error on every run forever.

Sources consulted: rmusser01/Infosec_Reference Draft/PrivescPostExmac.md
(Persistence and Privilege Escalation sections) and Draft/DFIR.md (OS X
Forensics), read 2026-09-16.

**Honest absence.** A location that does not exist is normal and yields
nothing. A location that exists but cannot be listed (permissions, I/O)
is returned in `unavailable`, never treated as empty — the caller records
it as a scan error, so a locked directory can never look like a clean one.

`program_path` is what the code-signing check runs against: the bundle
itself for bundle kinds (`codesign` verifies a bundle as a whole, and a
codeless kext has no executable to name), the file itself for script
kinds.
"""

from __future__ import annotations

import base64
import hashlib
import plistlib
import re
from pathlib import Path
from typing import Dict, List, Tuple

from secure.persistence._shell import run
from secure.storage.models.macos_readonly import MacDatabaseUnavailable, read_tcc_grants

_HOME = Path.home()

# kind -> (mode, [locations]). "bundle": each child of a directory whose
# name ends in one of the suffixes; "children": every non-hidden child of a
# directory; "files": each listed path that exists. Replaced wholesale by
# tests and validate scenarios, exactly like launch_items._LAUNCH_ITEM_DIRECTORIES.
_EXTRA_LOCATIONS: Dict[str, Tuple[str, List[Path]]] = {
    "authorization_plugin": ("bundle:.bundle", [Path("/Library/Security/SecurityAgentPlugins")]),
    "scripting_addition": ("bundle:.osax", [Path("/Library/ScriptingAdditions"), _HOME / "Library" / "ScriptingAdditions"]),
    "kernel_extension": ("bundle:.kext", [Path("/Library/Extensions")]),
    "startup_item": ("children", [Path("/Library/StartupItems")]),
    "periodic_script": ("files", [Path("/etc/daily.local"), Path("/etc/weekly.local"), Path("/etc/monthly.local")]),
    "emond_rule": ("bundle:.plist", [Path("/etc/emond.d/rules")]),
    "folder_action_script": ("children", [_HOME / "Library" / "Scripts" / "Folder Action Scripts"]),
    "ssh_rc": ("files", [_HOME / ".ssh" / "rc", Path("/etc/ssh/sshrc")]),
    "system_crontab": ("files", [Path("/etc/crontab")]),
    "at_job": ("children", [Path("/usr/lib/cron/jobs")]),
    "cron_job": ("crontab", [Path("/usr/bin/crontab")]),
    "system_extension": ("sysext", [Path("/usr/bin/systemextensionsctl")]),
    "configuration_profile": ("profiles", [Path("/usr/bin/profiles")]),
    "tcc_grant": ("tcc", [Path("/Library/Application Support/com.apple.TCC/TCC.db"),
                          _HOME / "Library" / "Application Support" / "com.apple.TCC" / "TCC.db"]),
    "hosts_entry": ("hosts", [Path("/etc/hosts")]),
    "resolver_file": ("children", [Path("/etc/resolver")]),
    "manual_dns_server": ("dnsservers", [Path("/usr/sbin/networksetup")]),
    "trusted_root": ("trust", [Path("/usr/bin/security")]),
    "ssh_authorized_key": ("authorized_keys", [_HOME / ".ssh" / "authorized_keys", _HOME / ".ssh" / "authorized_keys2"]),
}


def _bundle_label(path: Path) -> str:
    """CFBundleIdentifier when the bundle's Info.plist says so, else its name."""
    try:
        with (path / "Contents" / "Info.plist").open("rb") as f:
            identifier = plistlib.load(f).get("CFBundleIdentifier")
        if isinstance(identifier, str) and identifier:
            return identifier
    except (OSError, plistlib.InvalidFileException, ValueError, AttributeError):
        pass
    return path.name


# A key line is [options] keytype base64 [comment]; options may hold quoted
# spaces, so the key type is found rather than split on.
_KEY_RE = re.compile(r"(?:^|\s)((?:ssh|ecdsa|sk)-[A-Za-z0-9@._-]+)\s+([A-Za-z0-9+/]+={0,3})(?:\s+(.*))?$")
_CRON_ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=")


def _crontab_entries(kind: str, crontab: Path) -> Tuple[List[Dict[str, object]], List[str]]:
    result = run([str(crontab), "-l"])
    if result.returncode == 1 and "no crontab" in result.stderr.lower():
        return [], []
    if not result.ok:
        return [], [f"{kind}: {crontab} -l: {(result.stderr or 'exit ' + str(result.returncode)).strip()}"]
    entries = []
    for raw in result.stdout.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or _CRON_ENV_RE.match(line):
            continue
        fields = line.split(None, 1 if line.startswith("@") else 5)
        command = fields[-1] if len(fields) == (2 if line.startswith("@") else 6) else ""
        first = command.split(None, 1)[0] if command else ""
        digest = hashlib.sha256(line.encode()).hexdigest()[:16]
        entries.append({"kind": kind, "path": f"crontab:{digest}", "label": line[:200],
                        "program_path": first if first.startswith("/") else None,
                        "run_at_load": None, "keep_alive": None})
    return entries, []


def _authorized_key_entries(kind: str, path: Path) -> Tuple[List[Dict[str, object]], List[str]]:
    try:
        if not path.is_file():
            return [], []
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [], [f"{kind}: {path}: {type(exc).__name__}: {exc}"]
    entries = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _KEY_RE.search(line)
        fingerprint = None
        if match:
            try:
                blob = base64.b64decode(match.group(2), validate=True)
                fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
            except ValueError:
                fingerprint = None
        if fingerprint is None:
            # Unparseable is not ignorable: sshd may still accept a line this
            # parser does not understand, so it is listed, never skipped.
            digest = hashlib.sha256(line.encode()).hexdigest()[:16]
            entries.append({"kind": kind, "path": f"{path}#unparsed:{digest}",
                            "label": f"unparseable line {number}", "program_path": None,
                            "run_at_load": None, "keep_alive": None})
            continue
        options = line[:match.start(1)].strip()
        label = " ".join(p for p in (match.group(1), (match.group(3) or "").strip()) if p)
        if "command=" in options:
            label += " [forced command]"
        entries.append({"kind": kind, "path": f"{path}#{fingerprint}", "label": label,
                        "program_path": None, "run_at_load": None, "keep_alive": None})
    return entries, []


# Matched from the team id on: the enabled/active columns are "*" or blank.
_SYSEXT_ROW_RE = re.compile(r"(\S+)\s+(\S+)\s+\(([^)]*)\)\s+(.*?)\s+\[([^\]]*)\]\s*$")
_PROFILE_ID_RE = re.compile(r"^(\S+?)\[\d+\]\s+attribute:\s+profileIdentifier:\s+(\S+)")


def _plain_entry(kind: str, path: str, label: str) -> Dict[str, object]:
    return {"kind": kind, "path": path, "label": label, "program_path": None,
            "run_at_load": None, "keep_alive": None}


def _sysext_entries(kind: str, tool: Path) -> Tuple[List[Dict[str, object]], List[str]]:
    result = run([str(tool), "list"], timeout=10.0)
    if not result.ok:
        return [], [f"{kind}: {tool} list: {(result.stderr or 'exit ' + str(result.returncode)).strip()}"]
    lines = result.stdout.splitlines()
    declared = re.match(r"^\s*(\d+) extension\(s\)", lines[0]) if lines else None
    entries = []
    for line in lines:
        row = _SYSEXT_ROW_RE.search(line)
        if row and row.group(1) != "teamID":
            team, bundle_id, version, name, state = row.groups()
            entries.append(_plain_entry(kind, f"sysext:{team}:{bundle_id}", f"{name} {bundle_id} ({version}) [{state}]"))
    if declared is None or int(declared.group(1)) != len(entries):
        # The tool said how many it has; not finding that many rows means the
        # output format moved, and a short list must not pass as complete.
        return entries, [f"{kind}: {tool} list: parsed {len(entries)} row(s), tool declared "
                         f"{declared.group(1) if declared else 'no count'}"]
    return entries, []


def _profile_entries(kind: str, tool: Path) -> Tuple[List[Dict[str, object]], List[str]]:
    entries, problems = [], []
    listed = run([str(tool), "list"], timeout=10.0)
    if listed.ok:
        for line in listed.stdout.splitlines():
            match = _PROFILE_ID_RE.match(line.strip())
            if match:
                scope, identifier = match.groups()
                entries.append(_plain_entry(kind, f"profile:{scope}:{identifier}", f"{identifier} ({scope})"))
    else:
        problems.append(f"{kind}: {tool} list: {(listed.stderr or 'exit ' + str(listed.returncode)).strip()}")
    status = run([str(tool), "status", "-type", "enrollment"], timeout=10.0)
    if status.ok:
        for line in status.stdout.splitlines():
            key, _, value = line.partition(":")
            if value.strip().lower().startswith("yes"):
                entries.append(_plain_entry(kind, f"enrollment:{key.strip()}", line.strip()))
    else:
        problems.append(f"{kind}: {tool} status: {(status.stderr or 'exit ' + str(status.returncode)).strip()}")
    return entries, problems


def _entry(kind: str, path: Path, label: str) -> Dict[str, object]:
    return {"kind": kind, "path": str(path), "label": label, "program_path": str(path),
            "run_at_load": None, "keep_alive": None}


# The TCC services malware and stalkerware ask for. Others (contacts,
# calendars, AppleEvents automation) are real but far noisier.
_SENSITIVE_TCC_SERVICES = {
    "kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
    "kTCCServiceSystemPolicySysAdminFiles": "Administer files",
    "kTCCServiceScreenCapture": "Screen Recording",
    "kTCCServiceAccessibility": "Accessibility",
    "kTCCServiceListenEvent": "Input Monitoring",
    "kTCCServicePostEvent": "Synthetic input",
    "kTCCServiceCamera": "Camera",
    "kTCCServiceMicrophone": "Microphone",
    "kTCCServiceDeveloperTool": "Developer Tools",
    "kTCCServiceEndpointSecurityClient": "Endpoint Security",
}
_TCC_ALLOWED = {2: "allowed", 3: "limited"}


def _tcc_entries(kind: str, database: Path) -> Tuple[List[Dict[str, object]], List[str]]:
    try:
        grants = read_tcc_grants(database)
    except MacDatabaseUnavailable as exc:
        if not database.exists():
            return [], []
        hint = " (grant Full Disk Access to the app running Secure to read it)" if "unable to open" in str(exc) else ""
        return [], [f"{kind}: {exc}{hint}"]
    entries = []
    for grant in grants:
        name = _SENSITIVE_TCC_SERVICES.get(grant.service)
        if name is None or grant.auth_value not in _TCC_ALLOWED:
            continue
        entries.append({
            "kind": kind,
            "path": f"tcc:{database}:{grant.service}:{grant.client}",
            "label": f"{name} {_TCC_ALLOWED[grant.auth_value]}: {grant.client}",
            # A path client is an executable codesign can judge; a bundle id is not a path.
            "program_path": grant.client if grant.client_type == 1 and grant.client.startswith("/") else None,
            "run_at_load": None, "keep_alive": None,
        })
    return entries, []


_HOSTS_DEFAULTS = {("127.0.0.1", "localhost"), ("255.255.255.255", "broadcasthost"), ("::1", "localhost")}


def _hosts_entries(kind: str, path: Path) -> Tuple[List[Dict[str, object]], List[str]]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return [], []
    except OSError as exc:
        return [], [f"{kind}: {path}: {type(exc).__name__}: {exc}"]
    entries = []
    for raw in text.splitlines():
        fields = raw.split("#", 1)[0].split()
        if len(fields) < 2:
            continue
        address = fields[0]
        for name in fields[1:]:
            if (address, name) not in _HOSTS_DEFAULTS:
                entries.append(_plain_entry(kind, f"hosts:{name}:{address}", f"{name} -> {address}"))
    return entries, []


def _dns_server_entries(kind: str, tool: Path) -> Tuple[List[Dict[str, object]], List[str]]:
    listed = run([str(tool), "-listallnetworkservices"], timeout=10.0)
    if not listed.ok:
        return [], [f"{kind}: {tool} -listallnetworkservices: {(listed.stderr or 'exit ' + str(listed.returncode)).strip()}"]
    services = [line.lstrip("*").strip() for line in listed.stdout.splitlines()[1:] if line.strip()]
    if not services:
        return [], [f"{kind}: {tool} -listallnetworkservices: no network services parsed"]
    entries, problems = [], []
    for service in services:
        result = run([str(tool), "-getdnsservers", service], timeout=10.0)
        if not result.ok:
            problems.append(f"{kind}: {tool} -getdnsservers {service}: "
                            f"{(result.stderr or 'exit ' + str(result.returncode)).strip()}")
            continue
        for line in result.stdout.splitlines():
            server = line.strip()
            if not server or server.lower().startswith("there aren't any dns servers"):
                continue
            entries.append(_plain_entry(kind, f"dns:{service}:{server}", f"{service}: {server}"))
    return entries, problems


_TRUST_COUNT_RE = re.compile(r"^Number of trusted certs = (\d+)")
_TRUST_CERT_RE = re.compile(r"^Cert \d+: (.+)$")


def _trust_entries(kind: str, tool: Path) -> Tuple[List[Dict[str, object]], List[str]]:
    entries, problems = [], []
    for domain, flags in (("user", []), ("admin", ["-d"])):
        result = run([str(tool), "dump-trust-settings", *flags], timeout=10.0)
        if result.returncode == 1 and "no trust settings were found" in result.stderr.lower():
            continue
        if not result.ok:
            problems.append(f"{kind}: {tool} dump-trust-settings {' '.join(flags)}: "
                            f"{(result.stderr or 'exit ' + str(result.returncode)).strip()}")
            continue
        lines = result.stdout.splitlines()
        declared = _TRUST_COUNT_RE.match(lines[0]) if lines else None
        found = [m.group(1).strip() for m in map(_TRUST_CERT_RE.match, lines) if m]
        entries.extend(_plain_entry(kind, f"trust:{domain}:{name}", f"{name} ({domain} trust)") for name in found)
        if declared is None or int(declared.group(1)) != len(found):
            problems.append(f"{kind}: {domain} trust settings: parsed {len(found)} cert(s), tool declared "
                            f"{declared.group(1) if declared else 'no count'}")
    return entries, problems


_READERS = {
    "trust": _trust_entries,
    "hosts": _hosts_entries,
    "dnsservers": _dns_server_entries,
    "crontab": _crontab_entries,
    "authorized_keys": _authorized_key_entries,
    "sysext": _sysext_entries,
    "profiles": _profile_entries,
    "tcc": _tcc_entries,
}


def scan_extra_locations() -> Tuple[List[Dict[str, object]], List[str]]:
    """Every entry in every extra location, plus the locations that exist
    but could not be read. Returns (entries, unavailable) where each
    unavailable item is "<kind>: <path>: <error>".
    """
    entries: List[Dict[str, object]] = []
    unavailable: List[str] = []
    for kind, (mode, locations) in _EXTRA_LOCATIONS.items():
        for location in locations:
            if mode in _READERS:
                reader = _READERS[mode]
                found, problems = reader(kind, location)
                entries.extend(found)
                unavailable.extend(problems)
                continue
            if mode == "files":
                try:
                    if location.is_file():
                        entries.append(_entry(kind, location, location.name))
                except OSError as exc:
                    unavailable.append(f"{kind}: {location}: {type(exc).__name__}: {exc}")
                continue
            try:
                if not location.is_dir():
                    continue
                children = sorted(location.iterdir())
            except OSError as exc:
                unavailable.append(f"{kind}: {location}: {type(exc).__name__}: {exc}")
                continue
            for child in children:
                if child.name.startswith("."):
                    continue
                if mode.startswith("bundle:"):
                    if child.suffix != mode.split(":", 1)[1]:
                        continue
                    label = _bundle_label(child) if child.is_dir() else child.name
                else:
                    label = child.name
                entries.append(_entry(kind, child, label))
    return entries, unavailable
