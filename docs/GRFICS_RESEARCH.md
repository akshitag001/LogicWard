# GRFICS v3: Deep Research & Capabilities Report

Based on a deep dive into the Fortiphyd Logic GRFICS v3 repository, academic papers, and online discussions, here is a comprehensive breakdown of the "3D thing" we are using. This document will fully prepare you to answer any questions from the judges about the technology stack and its possibilities.

## What is GRFICS v3?
**GRFICS** (Graphical Realism Framework for Industrial Control Simulation) is an open-source, fully containerized platform developed by **Fortiphyd Logic** (originally stemming from research at Georgia Tech). 

Its primary purpose is to lower the barrier to entry for OT (Operational Technology) and ICS (Industrial Control Systems) cybersecurity training. By replacing expensive, dangerous physical hardware with a highly realistic 3D physics simulation, it allows practitioners to safely practice both offensive and defensive cybersecurity workflows.

## The 3D Engine & Architecture
The 3D environment we are using is a **WebGL application built in Unity**. 

### How it Communicates
Unlike typical video games, the Unity engine in GRFICS does *not* contain the physics logic itself. Instead, the architecture works like this:
1. **The Physics Engine (Python):** Our backend (`datastore.py`) runs the actual fluid dynamics calculations (pressure, level, stoichiometry) in a headless environment.
2. **Modbus TCP:** The physics engine exposes these real-time values as standard Modbus Holding Registers and Coils.
3. **The 3D Renderer (Unity):** The Unity WebGL client simply polls a `/data/index.php` endpoint via JSON to grab the current state of the physics engine. It then updates the 3D models (dials, valves, liquid levels) to match the data.

### Built-in 3D Animations & Visuals
The Unity WebGL build we are using (the Chemical Plant scenario) contains the following hardcoded animations that respond to the JSON data feed:
- **Liquid Level:** The purple fluid inside the main reactor rises and falls smoothly based on the tank percentage.
- **Valves:** The rotary actuator wheels on top of the pipes visually rotate to indicate open/closed percentages.
- **Gauges & Dials:** The digital displays above the pipes show exact flow rates and pressure readouts.
- **The Catastrophic Explosion:** If the pressure register exceeds the tank's structural limit, the Unity engine triggers a spectacular particle-physics explosion, blowing the top off the reactor.
- **First-Person Walkthrough:** The user can use WASD keys to physically walk around the plant to inspect the layout.

*(Note: The Unity game does NOT have built-in animations for liquid color changing or pump propellers spinning, which is why we removed the Chemical Spoilage attack earlier).*

## Why This is Powerful for Our Adani Project

1. **Safety & Cost:** Real chemical reactors cost millions of dollars and are extremely dangerous. By using GRFICS, we can demonstrate catastrophic physical consequences (like the tank exploding) safely in a browser. This guarantees an engaging demonstration for the judges.
2. **True Protocol Authenticity:** Because the 3D game strictly obeys standard OT protocols (Modbus), it proves that our attacks are not just "video game hacks." We are executing real-world Modbus payload injections, and the 3D plant is simply reacting exactly as a real plant would.
3. **Containerized Portability:** GRFICS v3 abandoned the heavy VirtualBox VMs of v2 in favor of Docker/containers. This means our entire integrated logic (both the Thermal Pi and the Chemical 3D plant) can run effortlessly on a single laptop for the presentation.

## Anticipating Judge Questions

**Q: "Is this just a video game you hacked?"**
*Answer:* "No. The 3D visualization is entirely passive. It simply renders the state of a separate, headless physics simulation. Our attacks are executing authentic Modbus TCP packets against a simulated PLC. If we plugged our code into a real physical chemical plant, the exact same explosion would happen."

**Q: "Why did you choose GRFICS over building your own simulation?"**
*Answer:* "GRFICS v3, developed by Fortiphyd Logic, is the gold standard for open-source OT cyber ranges. It allowed us to focus our engineering efforts on building the SOC dashboard, the drift-detection algorithms, and the actual attack payloads, rather than reinventing fluid dynamics equations."

**Q: "What are the limitations of this simulation?"**
*Answer:* "The visual renderer is limited to what was compiled into the WebGL bundle by Fortiphyd (pressure, level, valves). However, the underlying mathematical physics engine is entirely open-source Python, meaning we could theoretically simulate any complex chemical reaction mathematically, even if the 3D engine can't render every visual nuance."
