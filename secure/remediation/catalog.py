"""
Catalog — built-in remediation actions shipped with Secure.

Phase 48 ships 12 initial remediations covering firewall, SSH, services, and hardening.
All actions are defined as immutable dataclasses and execute through Phase 47's
verified safe-code infrastructure.
"""

from secure.remediation.models import (
    RemediationAction,
    RiskLevel,
    RemediationScope,
    RemediationVerification,
    VerificationType,
)


# Phase 48.1 initial catalog: 12 remediations
_CATALOG = {
    "firewall.enable": RemediationAction(
        id="firewall.enable",
        name="Enable macOS firewall",
        description="Enable the built-in macOS firewall if currently disabled.",
        risk_level=RiskLevel.LOW,
        action_type="firewall",
        change_request_template="templates/firewall_enable.jinja2",
        verification=RemediationVerification(
            type=VerificationType.CONFIG_CHECK,
            description="Verify firewall is enabled via `defaults read`",
            timeout_seconds=10,
        ),
        examples=[
            "attacker.disable-firewall-and-exfiltrate",
            "malware.disable-osx-firewall-for-persistence",
        ],
        references=[
            "https://attack.mitre.org/techniques/T1562/008/",
            "https://support.apple.com/en-us/HT201642",
        ],
    ),

    "firewall.block-inbound": RemediationAction(
        id="firewall.block-inbound",
        name="Block inbound connections to anomalous service",
        description="Add firewall rule to block incoming traffic to a newly-discovered listening service.",
        risk_level=RiskLevel.MEDIUM,
        action_type="firewall",
        change_request_template="templates/firewall_block_inbound.jinja2",
        verification=RemediationVerification(
            type=VerificationType.CONFIG_CHECK,
            description="Verify firewall rule exists",
            timeout_seconds=15,
        ),
        examples=[
            "persistence.unauthorized-service-listening",
        ],
    ),

    "ssh.disable-root-login": RemediationAction(
        id="ssh.disable-root-login",
        name="Disable SSH root login",
        description="Set PermitRootLogin no in sshd_config.",
        risk_level=RiskLevel.LOW,
        action_type="ssh",
        change_request_template="templates/ssh_disable_root_login.jinja2",
        verification=RemediationVerification(
            type=VerificationType.CONFIG_CHECK,
            description="Verify PermitRootLogin is set to no",
            timeout_seconds=10,
        ),
        examples=[
            "persistence.ssh-root-login",
            "attacker.brute-force-ssh-root",
        ],
        references=[
            "https://attack.mitre.org/techniques/T1021/004/",
            "https://man7.org/linux/man-pages/man5/sshd_config.5.html",
        ],
    ),

    "ssh.disable-password-auth": RemediationAction(
        id="ssh.disable-password-auth",
        name="Disable SSH password authentication",
        description="Set PasswordAuthentication no in sshd_config.",
        risk_level=RiskLevel.LOW,
        action_type="ssh",
        change_request_template="templates/ssh_disable_password_auth.jinja2",
        verification=RemediationVerification(
            type=VerificationType.CONFIG_CHECK,
            description="Verify PasswordAuthentication is set to no",
            timeout_seconds=10,
        ),
        examples=[
            "attacker.ssh-brute-force",
            "persistence.weak-ssh-creds",
        ],
    ),

    "service.disable-launchagent": RemediationAction(
        id="service.disable-launchagent",
        name="Disable suspicious LaunchAgent",
        description="Move a user LaunchAgent to a quarantine directory instead of deleting (preserves evidence).",
        risk_level=RiskLevel.MEDIUM,
        action_type="service",
        change_request_template="templates/service_disable_launchagent.jinja2",
        verification=RemediationVerification(
            type=VerificationType.SCAN_COMPARISON,
            description="Re-run persistence scan; verify agent no longer loads",
            timeout_seconds=60,
        ),
        examples=[
            "persistence.unauthorized-launchagent",
            "malware.launchagent-persistence",
        ],
        references=[
            "https://attack.mitre.org/techniques/T1547/013/",
        ],
    ),

    "service.disable-launchdaemon": RemediationAction(
        id="service.disable-launchdaemon",
        name="Disable suspicious LaunchDaemon",
        description="Rename a system LaunchDaemon to disable it (requires some privileges, but no sudo).",
        risk_level=RiskLevel.MEDIUM,
        action_type="service",
        change_request_template="templates/service_disable_launchdaemon.jinja2",
        verification=RemediationVerification(
            type=VerificationType.SCAN_COMPARISON,
            description="Re-run persistence scan; verify daemon no longer loads",
            timeout_seconds=60,
        ),
        examples=[
            "persistence.unauthorized-launchdaemon",
        ],
    ),

    "network.isolate-destination": RemediationAction(
        id="network.isolate-destination",
        name="Isolate network destination via lo0 routing",
        description="Route traffic to an anomalous remote IP through localhost (safe, non-blocking isolation).",
        risk_level=RiskLevel.HIGH,
        action_type="network",
        change_request_template="templates/network_isolate_destination.jinja2",
        verification=RemediationVerification(
            type=VerificationType.PROCESS_CHECK,
            description="Verify routing rule exists and connection fails",
            timeout_seconds=20,
        ),
        examples=[
            "network.c2-exfiltration",
            "attacker.data-ex fil to-known-bad-ip",
        ],
    ),

    "process.alert-on-relaunch": RemediationAction(
        id="process.alert-on-relaunch",
        name="Flag if killed process relaunches",
        description="Raise a HIGH alert if a process we stopped relaunches within 5 minutes (sign of persistence).",
        risk_level=RiskLevel.LOW,
        action_type="process",
        change_request_template="templates/process_alert_on_relaunch.jinja2",
        verification=RemediationVerification(
            type=VerificationType.MANUAL,
            description="User monitors for relaunch alert",
            timeout_seconds=300,
        ),
        examples=[
            "persistence.process-respawning",
        ],
    ),

    "config.harden-umask": RemediationAction(
        id="config.harden-umask",
        name="Set restrictive umask",
        description="Add umask 077 to shell rc files to prevent world-readable new files.",
        risk_level=RiskLevel.LOW,
        action_type="config",
        change_request_template="templates/config_harden_umask.jinja2",
        verification=RemediationVerification(
            type=VerificationType.CONFIG_CHECK,
            description="Verify umask 077 in .bashrc, .zshrc, etc.",
            timeout_seconds=10,
        ),
        examples=[
            "hardening.insecure-file-permissions",
        ],
    ),

    "credential.recommend-rotation": RemediationAction(
        id="credential.recommend-rotation",
        name="Recommend SSH key rotation",
        description="Create a user-actionable finding recommending SSH key rotation (no direct action).",
        risk_level=RiskLevel.LOW,
        action_type="credential",
        change_request_template="templates/credential_recommend_rotation.jinja2",
        verification=RemediationVerification(
            type=VerificationType.MANUAL,
            description="User rotates SSH keys and confirms",
            timeout_seconds=86400,  # 24 hours for user action
        ),
        examples=[
            "attack.compromised-ssh-key",
        ],
    ),

    "endpoint.mdm-notify": RemediationAction(
        id="endpoint.mdm-notify",
        name="Notify paired MDM of finding",
        description="Send finding to a paired Mobile Device Management system (if configured).",
        risk_level=RiskLevel.MEDIUM,
        action_type="endpoint",
        change_request_template="templates/endpoint_mdm_notify.jinja2",
        verification=RemediationVerification(
            type=VerificationType.MANUAL,
            description="Verify MDM received notification",
            timeout_seconds=30,
        ),
        examples=[
            "integration.mdm-escalation",
        ],
    ),

    "threat-hunt.priority-flag": RemediationAction(
        id="threat-hunt.priority-flag",
        name="Raise detection priority in correlation",
        description="Increase anomaly score weight for this finding in cross-module correlation.",
        risk_level=RiskLevel.LOW,
        action_type="threat-hunt",
        change_request_template="templates/threat_hunt_priority_flag.jinja2",
        verification=RemediationVerification(
            type=VerificationType.CONFIG_CHECK,
            description="Verify priority weight updated in correlation config",
            timeout_seconds=10,
        ),
        examples=[
            "correlation.boost-signal-weight",
        ],
    ),
}


def load_catalog() -> dict[str, RemediationAction]:
    """Load the complete remediation catalog."""
    return _CATALOG.copy()


def get_action(action_id: str) -> RemediationAction | None:
    """Get a single action by ID."""
    return _CATALOG.get(action_id)


def list_actions(
    risk_level: str | None = None,
    action_type: str | None = None,
    enabled_only: bool = True,
) -> list[RemediationAction]:
    """List actions, optionally filtered."""
    result = list(_CATALOG.values())

    if enabled_only:
        result = [a for a in result if a.enabled]

    if risk_level:
        result = [a for a in result if a.risk_level.value == risk_level]

    if action_type:
        result = [a for a in result if a.action_type == action_type]

    return sorted(result, key=lambda a: a.id)
