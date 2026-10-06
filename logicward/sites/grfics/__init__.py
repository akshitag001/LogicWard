"""GRFICS v3 chemical reactor — LogicWard Site B.

Drives the real Fortiphyd GRFICS Unity WebGL scene from a Python reactive
process model exposed over Modbus TCP (LogicWard's raw-socket server), so
attacks are real Modbus writes, the 3D plant visibly reacts, and LogicWard's
register-drift detector raises the same severity/MITRE-mapped events it does for
the thermal plant.
"""
SITE_ID = "grfics-chem"
SITE_NAME = "GRFICS Chemical Reactor"
