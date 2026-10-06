"""The bridge between the L5X program and Modbus live reality.

Maps each L5X tag (process value, setpoint, or coil) to a concrete Modbus
address + engineering scaling. This lets:
  * the plant seed/drive registers that mirror the tags the ladder references,
  * the drift engine read live setpoints over Modbus and corroborate them
    against the L5X (the "register truth" half of detection),
  * the dashboard render a live thermal-plant mimic from raw register reads.

Modbus registers are 16-bit integers, so real values carry an integer `scale`
(engineering value = raw / scale).  Areas: IR = input register (read-only
sensor), HR = holding register (read/write setpoint), C = coil, DI = discrete
input.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Point:
    area: str          # "IR" | "HR" | "C" | "DI"
    address: int
    tag: str           # L5X tag name
    unit: str
    scale: int = 1     # engineering value = raw / scale


# ── Input registers — read-only sensor values (the live process) ──────────────
INPUT_REGISTERS: list[Point] = [
    Point("IR", 0, "Generator_MW",       "MW",   1),
    Point("IR", 1, "Steam_Pressure",     "bar",  10),
    Point("IR", 2, "Main_Steam_Temp",    "degC", 1),
    Point("IR", 3, "Drum_Level",         "mm",   1),
    Point("IR", 4, "Turbine_Speed",      "rpm",  1),
    Point("IR", 5, "Condenser_Vacuum",   "mbar", 1),
    Point("IR", 6, "Bearing_Vibration",  "mm/s", 10),
]

# ── Holding registers — writable setpoints (mirror the L5X *_SP tags) ──────────
HOLDING_REGISTERS: list[Point] = [
    Point("HR", 0, "Steam_Press_HH_SP",     "bar",  10),
    Point("HR", 1, "Drum_Level_LL_SP",      "mm",   1),
    Point("HR", 2, "Turbine_Overspeed_SP",  "rpm",  1),
    Point("HR", 3, "Condenser_Vac_LO_SP",   "mbar", 1),
    Point("HR", 4, "Bearing_Vib_HI_SP",     "mm/s", 10),
    Point("HR", 5, "Load_Setpoint_MW",      "MW",   1),
]

# ── Coils — read/write bits (actuators + trip outputs) ────────────────────────
COILS: list[Point] = [
    Point("C", 0,  "Plant_Running",             "bool"),
    Point("C", 1,  "Feedwater_Pump_1",          "bool"),
    Point("C", 2,  "Feedwater_Pump_2",          "bool"),
    Point("C", 3,  "Fuel_Valve_Open",           "bool"),
    Point("C", 4,  "Main_Steam_Valve_Open",     "bool"),
    Point("C", 5,  "Generator_Breaker_Closed",  "bool"),
    Point("C", 6,  "Vibration_Alarm",           "bool"),
    Point("C", 7,  "Feedwater_Trip",            "bool"),
    Point("C", 8,  "Main_Steam_Trip",           "bool"),
    Point("C", 9,  "Turbine_Trip",              "bool"),
    Point("C", 10, "Fuel_Trip",                 "bool"),
    Point("C", 11, "Condenser_Trip",            "bool"),
]

# ── Discrete inputs — read-only status bits ───────────────────────────────────
DISCRETE_INPUTS: list[Point] = [
    Point("DI", 0, "Flame_Detected",        "bool"),
    Point("DI", 1, "Drum_Level_Sensor_OK",  "bool"),
    Point("DI", 2, "Vacuum_Sensor_OK",      "bool"),
]

ALL_POINTS: list[Point] = INPUT_REGISTERS + HOLDING_REGISTERS + COILS + DISCRETE_INPUTS

# name-indexed views
BY_TAG: dict[str, Point] = {p.tag: p for p in ALL_POINTS}
SETPOINT_TAGS: list[str] = [p.tag for p in HOLDING_REGISTERS if p.tag.endswith("_SP")]


def tag_point(tag: str) -> Point | None:
    return BY_TAG.get(tag)


def eng(raw: int, tag: str) -> float:
    """Convert a raw register value to its engineering value for `tag`."""
    p = BY_TAG.get(tag)
    return raw / p.scale if p else float(raw)


def raw(value: float, tag: str) -> int:
    """Convert an engineering value to the raw register integer for `tag`."""
    p = BY_TAG.get(tag)
    return int(round(value * p.scale)) if p else int(value)
