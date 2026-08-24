"""
secure/investigate/ — Phase 23: the entity-centric investigation
engine. Turns Secure from primarily an alert viewer into a tool for
pivoting among everything already known about one process, file,
destination, persistence item, or finding.

Hard rules, mirroring secure/explain/'s own founding discipline:

    1. Read-only by default. Nothing in this package writes to the
       database. Marking an alert known/unknown stays exactly where it
       already lives, per module — this package never duplicates that.
    2. No new detection logic. Every fact this package surfaces is
       read from a table some other module already wrote to, or
       derived deterministically from identity-string equality
       (the same "identity+timing, no fuzzy guessing" discipline
       secure/integrations/*/correlate.py already established) or from
       secure/evidence/'s own evidence_links graph. Nothing here scores,
       classifies, or infers.
    3. tkinter-independent. No import of tkinter, secure_gui, or
       anything GUI-specific anywhere in this package — the whole
       point is that a future frontend (CLI today, something else
       later) can present the same InvestigationView.
    4. Two addressing schemes, reused rather than invented:
         - EntityRef (entity_type, entity_key) — a durable, recurring
           real-world thing (see entity.py). Reuses
           secure/baseline/entities.py's vocabulary directly for every
           entity_type baseline already tracks; adds a small number of
           investigate-only types (destination, file, indicator) for
           pivot targets baseline has no reason to track.
         - ObservationRef (source_table, source_id) — one exact row,
           the same currency secure/evidence/ and secure/explain/
           already use. YARA/Sigma/Suricata/Zeek findings, anomalies,
           and correlated findings are EVIDENCE about an entity, not
           new recurring entities of their own — they're reached this
           way, not by inventing six more entity types.

See docs/INVESTIGATION.md for the full design.
"""

from __future__ import annotations
