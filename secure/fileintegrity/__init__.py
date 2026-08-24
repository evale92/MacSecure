"""
secure/fileintegrity/ — Phase 11: File Integrity Monitoring. See
scanner.py's module docstring for the full orchestration, and
PROJECT_NOTES.md for the phase-level writeup.
"""

from secure.fileintegrity.scanner import FileIntegrityScanResult, scan_file_integrity

__all__ = ["scan_file_integrity", "FileIntegrityScanResult"]
