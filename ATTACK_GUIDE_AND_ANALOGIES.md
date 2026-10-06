# LogicWard: OT Security Demo Attack Guide

This guide explains the 6 main attacks available in the LogicWard Red Team Console, exactly what they do under the hood, how the SOC detects them, and analogies to help explain them to the judges during your presentation.

---

## Modbus Attacks (Network Level)
These attacks simulate an adversary who has gained network access to the plant (e.g., via a compromised laptop) and is sending unauthorized commands directly to the PLC using the unencrypted, unauthenticated Modbus TCP protocol.

### 1. Setpoint Drift (`HIGH` Alert)
**What it does:** Sends a Modbus write command (FC 06) to silently change the "Drum Level Low-Low Trip" setpoint holding register from 220 mm down to 40 mm.
**The Impact:** The boiler's safety system is now "blind" to a dangerously low water level. If the drum runs dry, the PLC won't trip the plant until it hits 40mm (which is too late, risking a catastrophic boiler explosion).
**Analogy:** It’s like breaking into a building’s thermostat and changing the fire-sprinkler activation temperature from 100°F to 900°F. The sprinklers still work, but they will trigger way too late to stop the fire.
**SOC Detection:** The SOC's Drift Engine constantly polls the Modbus registers and compares them to the approved baseline. It detects that the `Drum_Level_LL_SP` tag changed unexpectedly over the network.
**Note on Program Diff:** This attack does *not* show up in the Program Diff tab because the actual `.L5X` code on the PLC wasn't changed—only the variables in memory were changed.

### 2. Force Coil (`LOW` Alert)
**What it does:** Sends a Modbus write command (FC 05) to force the `Fuel_Valve_Open` control coil to `False` (OFF).
**The Impact:** It instantly cuts the fuel supply to the boiler. The plant immediately trips on a flame-loss condition.
**Analogy:** It's the cyber equivalent of walking up to a pipe and manually slamming the fuel valve shut. 
**SOC Detection:** The SOC detects an unauthorized state change on a critical control coil over Modbus.

### 3. DDoS Flood (No Alert!)
**What it does:** Floods the PLC's Modbus server with rapid-fire read requests (FC 03), saturating the network and spiking the PLC's CPU.
**The Impact:** Legitimate traffic from the engineering workstation or HMI might get dropped or delayed.
**Analogy:** Like ordering 1,000 pizzas to someone's house so they can't answer the door when their real delivery arrives.
**Why no alert?** This is a key talking point! LogicWard is a *state-monitoring* SOC. It checks if the plant's logic or variables have changed. It does *not* monitor network traffic volume (it lacks a Network Intrusion Detection System). This proves to the judges why defense-in-depth requires both state-monitoring (LogicWard) AND network-monitoring (like Zeek/Snort).

---

## Program Download Attacks (Logic Level)
These attacks simulate an adversary pushing an entirely new, malicious `.L5X` program file to the PLC to fundamentally change how it operates.

### 4. Logic Inversion (`CRITICAL` Alert)
**What it does:** Modifies the L5X code to invert the drum-level trip comparator from `LES` (Less Than) to `GRT` (Greater Than). 
**The Impact:** The safety interlock is now backwards. It will trip the boiler when the drum is FULL instead of EMPTY.
**Analogy:** It's like rewiring your car's brakes so they only activate when you press the gas pedal.
**SOC Detection:** The SOC diffs the running L5X file against the baseline hash, detects the structural change, and specifically identifies that an operator (`LES`) was inverted to (`GRT`).

### 5. Condition Stripping (`CRITICAL` Alert)
**What it does:** Deletes a specific safety check (`XIC(Plant_Running)`) from the furnace flame-trip rung in the code.
**The Impact:** The fuel trip can now fire even when the plant is completely offline, which can cause severe operational confusion and unnecessary lockdown states.
**Analogy:** Like removing the "Must be in Park" safety check from a car, allowing you to start the engine while it's in drive.
**SOC Detection:** The SOC diffs the code and alerts that a critical safety condition was stripped from a specific rung.

### 6. Coil Hijack (`CRITICAL` Alert)
**What it does:** Rewires the output of the Feedwater emergency trip to point to the `Cooling_Pump_Stop` coil instead.
**The Impact:** A catastrophic mismatch. If a drum emergency occurs, the PLC will shut down the cooling pumps instead of the feedwater, accelerating the meltdown instead of stopping it.
**Analogy:** Like crossing the wires on a fire alarm so that pulling it activates the building's space heaters instead of the sprinklers.
**SOC Detection:** The SOC detects that an output coil was repointed to a different, unauthorized address.

### 7. Rung Injection (`CRITICAL` Alert)
**What it does:** Injects an entirely new, hidden backdoor rung into the PLC logic that allows the attacker to unlatch the turbine overspeed trip at will.
**The Impact:** The attacker has installed a persistent backdoor that is invisible to normal HMI operators, allowing them to disable the turbine's physical safety brakes.
**Analogy:** Like secretly adding a second, hidden steering wheel in the trunk of a car that overrides the driver in the front seat.
**SOC Detection:** The SOC detects an unauthorized `XIC(Attacker_Backdoor)` logic rung injected into the program file.
