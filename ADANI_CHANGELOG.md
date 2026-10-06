# Adani Project - Changelog & Modifications

This document tracks all modifications, UI upgrades, and bug fixes made to the LogicWard dashboard and Red Team Console in preparation for the Adani executive presentation. 

**Maintained by:** Komal & Antigravity

## [2026-07-30] Role-Based Access Control (RBAC) Upgrades
* **Added System Admin Role:** 
  * *Backend:* Modified `app.py` to include an `"admin"` role in the `USERS` dictionary with `ROLE_RANK = 4` (highest privilege).
  * *Frontend:* Modified `login.html` to add a new demo account button for the System Admin.
* **UI Polish (Login Screen):**
  * Renamed the "Demo accounts" header in `login.html` to "Quick Access Profiles — presentation mode" to sound more professional for an enterprise demo while keeping the one-click convenience.
* **Role Discrepancy Note (For Akshit):**
  * Currently, there are **6 conceptual roles** displayed on the static "Roles & Access" UI tab for the pitch. However, there are only **4 functional roles** programmed into the backend (`app.py`) and the login screen (Operator, Engineer, SOC Analyst, System Admin). This is a known state and will be completed by Akshit.
* **Frontend RBAC Security Fixes:**
  * Fixed privilege escalation bug in `app.js`. Replaced insecure `data-role-min` check with explicit `data-roles` whitelist checking.
  * Correctly hid Engineer controls (Re-lock baseline, Restore baseline) from the SOC Analyst and Operator views in `dashboard.html`.
* **Alert Feed Polish:**
  * Renamed the destructive "Clear Alerts" button to "Acknowledge All".
  * Granted the `operator` role permission to acknowledge alarms.

## Future Tracked Changes
*(Any further changes to the Thermal Plant, Dashboards, or UI will be tracked here.)*
