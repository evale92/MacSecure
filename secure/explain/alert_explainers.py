"""Per-module alert explainers — one small function per alert type.

Each function is built only from fields already on the corresponding
`secure.storage.models` record (kind/severity/subject fields/message).
None of them recompute severity, and none of them parse the `message`
string to extract facts — where a structured field already exists
(e.g. arpwatch's `mac`/`previous_mac`), it's used directly; where it
doesn't (most modules — see docs/EXPLAINABILITY.md's "what's not
captured yet" section), the stored `message` is reused verbatim as a
direct-observation evidence item rather than re-derived or guessed at.

Every function has a fallback branch for `kind` values it doesn't
specifically recognize — future kinds, or an older/newer schema this
explainer hasn't been updated for — via
`secure.explain.explanation.generic_explanation()`, so the Alerts
table always stays usable even if a new module or new kind is added
without also updating this file (see dispatch.py for the second,
outer layer of protection: any exception here still degrades to a
safe fallback rather than breaking the table).
"""

from __future__ import annotations

from secure.explain import vocab
from secure.explain.explanation import EvidenceItem, Explanation, generic_explanation, resolve_action

# ---------- ARP Watch ----------


def explain_arp_alert(record) -> Explanation:
    kind = record.kind

    if kind == "gateway_mac_changed":
        action, action_text = resolve_action(vocab.INVESTIGATE_NOW)
        return Explanation(
            summary=(
                "Your network's default gateway is now answering ARP as a "
                "different MAC address than in the previous scan."
            ),
            severity=record.severity,
            confidence=vocab.CONFIRMED,
            confidence_reason=(
                "The gateway's MAC address change is a direct ARP-table "
                "observation from this scan."
            ),
            significance=(
                "Because the gateway is the exit point for this device's network "
                "traffic, a spoofed gateway MAC could let another device on the "
                "network intercept or redirect that traffic."
            ),
            recommended_action=action,
            recommended_action_text=action_text,
            evidence=(
                EvidenceItem(f"Previous gateway MAC: {record.previous_mac or 'not recorded'}", vocab.DIRECT_OBSERVATION),
                EvidenceItem(f"Current gateway MAC: {record.mac or 'not recorded'}", vocab.DIRECT_OBSERVATION),
            ),
            correlated_events=(),
            uncertainty_status=vocab.UNCERTAINTY_KNOWN,
            uncertainty=(
                "Replacing or resetting your router/gateway hardware produces this exact pattern and is benign.",
                "An ISP-side change to your modem/router can also cause this.",
                "ARP spoofing of the gateway is a genuine attack pattern this can also indicate.",
            ),
        )

    if kind == "mac_changed":
        action, action_text = resolve_action(vocab.MONITOR)
        return Explanation(
            summary=f"{record.ip} is now answering ARP as a different MAC address than in the previous scan.",
            severity=record.severity,
            confidence=vocab.CONFIRMED,
            confidence_reason="The MAC address change for this IP is a direct ARP-table observation from this scan.",
            significance=(
                "This usually reflects routine network activity (a DHCP lease "
                "change or a device rejoining the network), but is also the "
                "pattern ARP spoofing produces."
            ),
            recommended_action=action,
            recommended_action_text=action_text,
            evidence=(
                EvidenceItem(f"Previous MAC: {record.previous_mac or 'not recorded'}", vocab.DIRECT_OBSERVATION),
                EvidenceItem(f"Current MAC: {record.mac or 'not recorded'}", vocab.DIRECT_OBSERVATION),
            ),
            correlated_events=(),
            uncertainty_status=vocab.UNCERTAINTY_KNOWN,
            uncertainty=(
                "DHCP lease changes and devices reconnecting after sleep/reboot commonly cause this and are benign.",
                "ARP spoofing on the local network can also produce this exact pattern.",
            ),
        )

    if kind == "ip_conflict":
        action, action_text = resolve_action(vocab.VERIFY_DEVICE)
        return Explanation(
            summary=f"More than one MAC address answered ARP for {record.ip} within a single scan.",
            severity=record.severity,
            confidence=vocab.CONFIRMED,
            confidence_reason="Multiple MAC addresses answering for one IP within a single scan is a direct ARP-table observation.",
            significance=(
                "This can indicate a simple IP address conflict between two of "
                "your own devices, or ARP spoofing attempting to intercept "
                "traffic addressed to this IP."
            ),
            recommended_action=action,
            recommended_action_text=action_text,
            evidence=(EvidenceItem(record.message, vocab.DIRECT_OBSERVATION),),
            correlated_events=(),
            uncertainty_status=vocab.UNCERTAINTY_KNOWN,
            uncertainty=(
                "A misconfigured static IP or a DHCP conflict between two of your own devices is a common benign cause.",
                "ARP spoofing/local network attacks can also produce this exact pattern.",
            ),
        )

    return generic_explanation(
        source_table="arp_alerts", severity=record.severity, message=record.message, subject=record.ip,
    )


# ---------- Wi-Fi ----------


def explain_wifi_alert(record) -> Explanation:
    if record.kind == "similar_ssid":
        action, action_text = resolve_action(vocab.CLASSIFY)
        return Explanation(
            summary=f"A network calling itself '{record.ssid}' closely resembles a network you already trust.",
            severity=record.severity,
            confidence=vocab.LIKELY,
            confidence_reason=(
                "The SSID similarity match is a deterministic string-similarity "
                "comparison already computed by the Wi-Fi scan — but 'resembles' "
                "is an interpretation, not a raw fact, so this stops short of CONFIRMED."
            ),
            significance=(
                "Attackers sometimes set up a lookalike ('evil twin') access point "
                "to trick devices into connecting automatically, then intercept traffic."
            ),
            recommended_action=action,
            recommended_action_text=action_text,
            evidence=(
                EvidenceItem(f"New SSID observed: {record.ssid}", vocab.DIRECT_OBSERVATION),
                EvidenceItem(record.message, vocab.SECURE_INTERPRETATION),
            ),
            correlated_events=(),
            uncertainty_status=vocab.UNCERTAINTY_KNOWN,
            uncertainty=(
                "This can be a legitimate neighboring network with a coincidentally similar name.",
                "It can also be an 'evil twin' access point set up to intercept connections intended for your trusted network.",
            ),
        )

    return generic_explanation(
        source_table="wifi_alerts", severity=record.severity, message=record.message, subject=record.ssid,
    )


# ---------- Bluetooth (classic) ----------


def explain_bluetooth_alert(record) -> Explanation:
    subject = record.name or record.identifier

    if record.kind == "new_pairing":
        action, action_text = resolve_action(vocab.VERIFY_DEVICE)
        return Explanation(
            summary=f"'{subject}' — previously unpaired and untrusted — has now paired with this Mac.",
            severity=record.severity,
            confidence=vocab.CONFIRMED,
            confidence_reason="The unpaired-to-paired state transition is a direct Bluetooth state observation.",
            significance=(
                "Pairing is a deliberate action — either you (or someone with "
                "physical/UI access to this Mac) approved it, or software "
                "completed it programmatically."
            ),
            recommended_action=action,
            recommended_action_text=action_text,
            evidence=(EvidenceItem(record.message, vocab.DIRECT_OBSERVATION),),
            correlated_events=(),
            uncertainty_status=vocab.UNCERTAINTY_KNOWN,
            uncertainty=(
                "You or someone with access to this Mac may have paired this device intentionally.",
                "Software can also complete a pairing without an obvious prompt you'd notice.",
            ),
        )

    if record.kind == "first_connection":
        action, action_text = resolve_action(vocab.CLASSIFY)
        return Explanation(
            summary=f"'{subject}' — untrusted — connected to this Mac for the first time.",
            severity=record.severity,
            confidence=vocab.CONFIRMED,
            confidence_reason="The not-connected-to-connected state transition is a direct Bluetooth state observation.",
            significance="An already-paired-but-untrusted device connecting is ordinary Bluetooth behavior, but worth recognizing.",
            recommended_action=action,
            recommended_action_text=action_text,
            evidence=(EvidenceItem(record.message, vocab.DIRECT_OBSERVATION),),
            correlated_events=(),
            uncertainty_status=vocab.UNCERTAINTY_KNOWN,
            uncertainty=(
                "A device you previously paired but haven't explicitly trusted can reconnect automatically — this is normal.",
                "If you don't recognize this device at all, that's worth a closer look.",
            ),
        )

    if record.kind == "persistent_unknown":
        action, action_text = resolve_action(vocab.MONITOR)
        return Explanation(
            summary=f"'{subject}' — untrusted — has now been seen nearby across several scans.",
            severity=record.severity,
            confidence=vocab.LIKELY,
            confidence_reason="Repeated appearance across multiple scans is a derived pattern built from several direct observations.",
            significance="Devices that repeatedly appear nearby without ever being trusted are usually just your own other devices or a neighbor's, but persistent proximity is worth an occasional look.",
            recommended_action=action,
            recommended_action_text=action_text,
            evidence=(EvidenceItem(record.message, vocab.DERIVED_FACT),),
            correlated_events=(),
            uncertainty_status=vocab.UNCERTAINTY_KNOWN,
            uncertainty=(
                "Common nearby devices (your phone, watch, earbuds, a neighbor's devices) routinely produce this.",
                "Persistent unknown proximity can also indicate a tracking or monitoring device.",
            ),
        )

    return generic_explanation(
        source_table="bluetooth_alerts", severity=record.severity, message=record.message, subject=subject,
    )


# ---------- Bluetooth LE ----------


def explain_ble_alert(record) -> Explanation:
    subject = record.name or record.cb_uuid

    if record.kind == "rssi_significant_change":
        action, action_text = resolve_action(vocab.MONITOR)
        return Explanation(
            summary=f"'{subject}'s advertised signal strength changed significantly since it was last seen.",
            severity=record.severity,
            confidence=vocab.CONFIRMED,
            confidence_reason="The signal-strength reading itself is a direct sensor observation; the significant-change pattern is a deterministic comparison against the previous reading.",
            significance="BLE signal strength naturally varies with distance and obstacles; a large jump usually just means the device (or you) moved.",
            recommended_action=action,
            recommended_action_text=action_text,
            evidence=(EvidenceItem(record.message, vocab.DERIVED_FACT),),
            correlated_events=(),
            uncertainty_status=vocab.UNCERTAINTY_KNOWN,
            uncertainty=(
                "Physical movement of you or the device is the most common cause.",
                "BLE devices frequently rotate their advertised address, which can occasionally cause two different physical devices to be tracked as if they were 'the same' peripheral.",
            ),
        )

    if record.kind == "persistent_unknown":
        action, action_text = resolve_action(vocab.MONITOR)
        return Explanation(
            summary=f"'{subject}' — untrusted — has now been seen nearby across several scans.",
            severity=record.severity,
            confidence=vocab.LIKELY,
            confidence_reason="Repeated appearance across multiple scans is a derived pattern built from several direct observations.",
            significance="BLE devices often rotate their advertised address every ~15 minutes, so this may undercount — or in rare cases conflate — distinct physical devices; persistent unknown proximity is still worth an occasional look.",
            recommended_action=action,
            recommended_action_text=action_text,
            evidence=(EvidenceItem(record.message, vocab.DERIVED_FACT),),
            correlated_events=(),
            uncertainty_status=vocab.UNCERTAINTY_KNOWN,
            uncertainty=(
                "Common nearby BLE devices (your own earbuds/watch/phone, neighbors' devices) routinely produce this.",
                "Persistent unknown proximity can also indicate a tracking or monitoring device.",
            ),
        )

    return generic_explanation(
        source_table="ble_alerts", severity=record.severity, message=record.message, subject=subject,
    )


# ---------- Process & Persistence ----------


def explain_persistence_alert(record) -> Explanation:
    subject = record.label or record.identifier

    if record.kind == "unusual_unsigned_process":
        action, action_text = resolve_action(vocab.INSPECT_PROCESS)
        if record.severity == "high":
            confidence, reason = (
                vocab.LIKELY,
                "High severity here means both an unsigned/ad-hoc-signed executable AND an unusual install location were observed together — two independent supporting signals.",
            )
        else:
            confidence, reason = (
                vocab.UNCERTAIN,
                "This severity level means only one of the two supporting signals (unsigned/ad-hoc code signing, unusual install location) was present, not both.",
            )
        return Explanation(
            summary=f"'{subject}' started running for the first time.",
            severity=record.severity,
            confidence=confidence,
            confidence_reason=reason,
            significance="New, unsigned executables in unusual locations are a common malware persistence pattern, but can also be legitimate developer tools or scripts you installed yourself.",
            recommended_action=action,
            recommended_action_text=action_text,
            evidence=(EvidenceItem(record.message, vocab.DIRECT_OBSERVATION),),
            correlated_events=(),
            uncertainty_status=vocab.UNCERTAINTY_KNOWN,
            uncertainty=(
                "Developer tools, scripts, and some legitimate utilities are unsigned or ad-hoc signed by design.",
                "Malware persistence commonly uses unsigned executables in unusual locations — this is also exactly that pattern.",
            ),
        )

    if record.kind == "new_persistence_entry":
        action, action_text = resolve_action(vocab.REVIEW_PERSISTENCE)
        if record.severity == "high":
            confidence, reason = (
                vocab.LIKELY,
                "High severity here means the startup item's program path could not be resolved, or its executable is unsigned/ad-hoc-signed.",
            )
        else:
            confidence, reason = (
                vocab.UNCERTAIN,
                "Medium severity is the default floor for any new startup item — it does not by itself indicate an unresolved path or a signing problem.",
            )
        return Explanation(
            summary=f"A new startup item ('{subject}') was registered.",
            severity=record.severity,
            confidence=confidence,
            confidence_reason=reason,
            significance="New LaunchAgents/LaunchDaemons/login items are one of the most common ways software persists across restarts — including both legitimate installers and malware.",
            recommended_action=action,
            recommended_action_text=action_text,
            evidence=(EvidenceItem(record.message, vocab.DIRECT_OBSERVATION),),
            correlated_events=(),
            uncertainty_status=vocab.UNCERTAINTY_KNOWN,
            uncertainty=(
                "Installing new legitimate software commonly adds a new startup item — expected right after installing an app.",
                "Malware persistence mechanisms frequently register a new LaunchAgent/LaunchDaemon this same way.",
            ),
        )

    if record.kind == "signing_changed":
        action, action_text = resolve_action(vocab.INVESTIGATE_NOW)
        return Explanation(
            summary=f"The executable behind '{subject}' changed code-signing status since the last scan.",
            severity=record.severity,
            confidence=vocab.CONFIRMED,
            confidence_reason="A code-signing status downgrade between two scans of the same startup item's backing executable is a direct comparison already computed by this scan.",
            significance="A previously Apple- or developer-signed executable being replaced by an unsigned/ad-hoc-signed one at the same startup entry is unusual — legitimate software updates are normally still signed.",
            recommended_action=action,
            recommended_action_text=action_text,
            evidence=(EvidenceItem(record.message, vocab.DIRECT_OBSERVATION),),
            correlated_events=(),
            uncertainty_status=vocab.UNCERTAINTY_KNOWN,
            uncertainty=(
                "A very recent update from a legitimate but not-yet-notarized build can occasionally trigger this.",
                "This is also the pattern produced by malware replacing a legitimate binary at the same startup location.",
            ),
        )

    return generic_explanation(
        source_table="persistence_alerts", severity=record.severity, message=record.message, subject=subject,
    )


# ---------- File Integrity ----------


def explain_file_integrity_alert(record) -> Explanation:
    subject = record.path

    def _finish(summary, significance, uncertainty, action_key, confidence=vocab.CONFIRMED, confidence_reason=None):
        action, action_text = resolve_action(action_key)
        return Explanation(
            summary=summary,
            severity=record.severity,
            confidence=confidence,
            confidence_reason=confidence_reason or "This comparison is made directly between two scans of the same path.",
            significance=significance,
            recommended_action=action,
            recommended_action_text=action_text,
            evidence=(EvidenceItem(record.message, vocab.DIRECT_OBSERVATION),),
            correlated_events=(),
            uncertainty_status=vocab.UNCERTAINTY_KNOWN,
            uncertainty=uncertainty,
        )

    if record.kind == "modified":
        return _finish(
            summary=f"The contents of {subject} changed.",
            significance="This means the file's actual contents changed, not just its metadata. That's expected after you or an installer edits/updates it, but is also how tampering would appear.",
            uncertainty=(
                "Software updates, configuration edits, and normal application behavior routinely modify files this way.",
                "This is also exactly the pattern unauthorized tampering would produce.",
            ),
            action_key=vocab.INSPECT_FILE,
            confidence_reason="A file content hash change between two scans of the same path is a direct, cryptographic comparison.",
        )

    if record.kind == "metadata_only":
        return _finish(
            summary=f"{subject}'s metadata (permissions, ownership, or similar) changed, without its contents changing.",
            significance="Ownership or permission changes on a sensitive/startup-related file can widen who is able to modify or run it.",
            uncertainty=(
                "Routine administration (reinstalling software, repairing permissions) can cause this.",
                "Permission/ownership changes are also a way to weaken a file's protections ahead of tampering.",
            ),
            action_key=vocab.INSPECT_FILE,
            confidence_reason="A metadata change between two scans of the same path is a direct comparison, independent of the file's content.",
        )

    if record.kind == "created":
        return _finish(
            summary=f"A new file appeared at {subject}.",
            significance="This is a location Secure watches specifically because software persistence or configuration commonly lives there.",
            uncertainty=(
                "Normal installs/updates often add new files in watched locations.",
                "This is also how new malicious persistence artifacts would first appear.",
            ),
            action_key=vocab.REVIEW_PERSISTENCE,
        )

    if record.kind == "deleted":
        return _finish(
            summary=f"A previously-watched file at {subject} is now gone.",
            significance="A watched file disappearing is worth understanding, especially for startup-related paths.",
            uncertainty=(
                "Uninstalling software or manual cleanup commonly removes files this way.",
                "Deletion can also be used to remove evidence or disable a security-relevant file.",
            ),
            action_key=vocab.INSPECT_FILE,
        )

    if record.kind == "renamed":
        return _finish(
            summary=f"A watched file was renamed or moved to/from {subject}.",
            significance="Same content, different path — worth understanding why, especially for startup-related paths.",
            uncertainty=(
                "Normal reorganization or renaming during updates or user action is a common benign cause.",
                "Renaming can also be used to relocate a file while evading a path-specific watch.",
            ),
            action_key=vocab.INSPECT_FILE,
            confidence=vocab.LIKELY,
            confidence_reason=(
                "Rename detection compares device/inode identity between scans; the "
                "message describes what Secure matched, but the underlying match "
                "confidence detail isn't carried on this alert record — see "
                "docs/EXPLAINABILITY.md for this documented gap."
            ),
        )

    if record.kind == "program_target_changed":
        return _finish(
            summary=f"A startup item's actual target program changed at {subject}.",
            significance="The startup item's declared identity may look unchanged while what it actually runs has been swapped — a known technique for hijacking an existing, already-trusted startup entry.",
            uncertainty=(
                "A legitimate app update can change or re-sign its own helper/launcher target.",
                "This is also a known technique for hijacking an existing, already-trusted startup entry.",
            ),
            action_key=vocab.REVIEW_PERSISTENCE,
            confidence_reason="The startup plist's target executable and its code-signing status are directly checked by this scan.",
        )

    return generic_explanation(
        source_table="file_integrity_alerts", severity=record.severity, message=record.message, subject=subject,
    )
