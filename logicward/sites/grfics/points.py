"""GRFICS chemical reactor point map — the Modbus address/scale table.

Mirrors the thermal `rung_to_register` idea for a different process, kept fully
self-contained so nothing thermal is touched. Areas: IR = live sensor
(read-only, not baselined — process noise), HR = writable command/setpoint
(baselined — attacker-controllable), C = coil (baselined), DI = status bit.

Register values are 16-bit ints; engineering value = raw / scale.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Point:
    area: str          # "IR" | "HR" | "C" | "DI"
    address: int
    tag: str
    unit: str
    scale: int = 1


# ── Input registers — live sensors (mapped to the Unity scene's outputs) ──────
INPUT_REGISTERS: list[Point] = [
    Point("IR", 0, "Reactor_Pressure", "kPa", 1),     # 0..4000  -> Unity "pressure"
    Point("IR", 1, "Liquid_Level",     "pct", 100),   # 0..120%  -> Unity "liquid_level"
    Point("IR", 2, "Feed1_Flow",       "u",   100),
    Point("IR", 3, "Feed2_Flow",       "u",   100),
    Point("IR", 4, "Purge_Flow",       "u",   100),
    Point("IR", 5, "Product_Flow",     "u",   100),
    Point("IR", 6, "A_Composition",    "pct", 100),
    Point("IR", 7, "B_Composition",    "pct", 100),
    Point("IR", 8, "C_Composition",    "pct", 100),
]

# ── Holding registers — operator commands + safety setpoints (baselined) ──────
HOLDING_REGISTERS: list[Point] = [
    Point("HR", 0, "Feed1_Valve_Cmd",   "pct", 100),  # 0..100% -> Unity "f1_valve_pos"
    Point("HR", 1, "Feed2_Valve_Cmd",   "pct", 100),  #            -> "f2_valve_pos"
    Point("HR", 2, "Purge_Valve_Cmd",   "pct", 100),  #            -> "purge_valve_pos"
    Point("HR", 3, "Product_Valve_Cmd", "pct", 100),  #            -> "product_valve_pos"
    Point("HR", 4, "Pressure_HH_SP",    "kPa", 1),     # safety trip setpoint (critical)
    Point("HR", 5, "Level_HH_SP",       "pct", 100),   # safety trip setpoint (critical)
]

# ── Coils — actuators / trips (baselined) ─────────────────────────────────────
COILS: list[Point] = [
    Point("C", 0, "Reactor_ESD",     "bool"),   # emergency shutdown -> Unity "e_stop"
    Point("C", 1, "Feed_Pump_1",     "bool"),
    Point("C", 2, "Feed_Pump_2",     "bool"),
    Point("C", 3, "Agitator_Running","bool"),
    Point("C", 4, "Pressure_Trip",   "bool"),   # plant-driven (own protection)
    Point("C", 5, "Level_Trip",      "bool"),   # plant-driven
]

# ── Discrete inputs — status bits ─────────────────────────────────────────────
DISCRETE_INPUTS: list[Point] = [
    Point("DI", 0, "Pressure_Sensor_OK", "bool"),
    Point("DI", 1, "Level_Sensor_OK",    "bool"),
]

ALL_POINTS = INPUT_REGISTERS + HOLDING_REGISTERS + COILS + DISCRETE_INPUTS
BY_TAG: dict[str, Point] = {p.tag: p for p in ALL_POINTS}

# Coils the plant drives itself every scan — excluded from register-integrity
# (their change is legitimate protection behaviour, not an attack).
PLANT_DRIVEN_COILS = {"Pressure_Trip", "Level_Trip"}

# Safety-critical setpoints — drift here escalates severity.
SAFETY_SETPOINTS = {"Pressure_HH_SP", "Level_HH_SP"}


def eng(raw: int, tag: str) -> float:
    p = BY_TAG.get(tag)
    return raw / p.scale if p else float(raw)


def raw(value: float, tag: str) -> int:
    p = BY_TAG.get(tag)
    return int(round(value * p.scale)) if p else int(value)
