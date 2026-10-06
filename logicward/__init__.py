"""LogicWard — live OT drift-detection appliance.

Detects unauthorized PLC logic changes on a simulated thermal power plant by
continuously diffing live Modbus reality + the running program against a hashed,
approved baseline. See DESIGN.md for the full specification.
"""

__version__ = "1.0.0"
