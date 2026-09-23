"""
Re-export MITRE ATT&CK reference data from secure/knowledge/attck.

Relocated to foundation tier in Phase 50 for intelligence module reuse.
This file maintains backward compatibility with existing validate imports.
"""

from secure.knowledge.attck import Technique, REGISTRY, T1547_011, T1036_005, T1204_002, T1571, T1071_001, T1562_001

__all__ = ["Technique", "REGISTRY", "T1547_011", "T1036_005", "T1204_002", "T1571", "T1071_001", "T1562_001"]
