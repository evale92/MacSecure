"""
secure/correlate — Cross-Module Correlation.

Every other module in this app answers "is THIS one thing worth a
look." This package asks a different question: do several of those
individually-modest findings, from DIFFERENT unrelated subsystems,
line up in time closely enough that the combination is more
interesting than any of them alone? A new unsigned process, a new
persistence entry, and a new outbound connection within the same
minute is a much stronger signal than any one of those three on its
own — that's what this package looks for.

Deliberately reads only the database — see secure/correlate/signals.py
for exactly which existing tables feed it and why. Never touches the
outside world, never acts on anything it finds; every correlation
alert is something you review yourself, same as every other alert in
this app. See PROJECT_NOTES.md's "Cross-Module Correlation" section for
the full explanation, including the weighted scoring model, the
weak-signal severity cap, and the benign-context annotations.
"""

from secure.correlate.scanner import CorrelationResult, correlate

__all__ = ["correlate", "CorrelationResult"]
