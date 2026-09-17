"""
secure.downloads — where the files on this Mac came from.

macOS records every file a quarantine-aware app (browsers, Mail,
Messages, Slack, AirDrop, ...) downloads in
~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2: the
app that fetched it, the file URL and the page it came from, and when.
It is the core download-provenance artifact in Mac incident response,
and nothing else in Secure could see it.

Point-in-time and operator-requested (`secure downloads`), read-only,
no new tables: the history already lives in macOS's own database and
copying it into Secure's would only give it a second place to go stale.

Flags are deterministic string rules (invariant 1), each one a reason to
look, not a verdict:

    executable_type   the file name ends in a type that runs or installs
                      code (.dmg, .pkg, .app, .command, .sh, .scpt, ...)
    ip_literal_host   the URL's host is a bare IP address, which ordinary
                      software distribution almost never uses
    plain_http        fetched over unencrypted http://

Tools that do not set the quarantine attribute (curl, wget, git, pip,
anything run in Terminal) never appear here. That limit is printed with
every report so an empty history can't be misread as "nothing was
downloaded".

Source: rmusser01/Infosec_Reference @af8b68e Draft/L-SM-TH.md ~1150
(mac4n6 "Unified Logs: Quarantine Edition") and Draft/DFIR.md ~539.
"""

from __future__ import annotations

from secure.downloads.history import DownloadEvent, DownloadReport, download_history

__all__ = ["DownloadEvent", "DownloadReport", "download_history"]
