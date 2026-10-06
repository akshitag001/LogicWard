# Security Policy

## Scope and intent

LogicWard is a **laboratory and demonstration tool** for OT/ICS drift detection. It
runs a *simulated* PLC and a deliberately insecure (unauthenticated) Modbus surface so
that attacks can be shown end to end. **It is not hardened for, or supported on,
production control networks.**

Known, intentional properties for the demo:
- The simulated PLC exposes **unauthenticated Modbus** and an **unauthenticated program
  download** endpoint — that is the threat being demonstrated, not a defect.
- **Demo mode** (`LOGICWARD_DEMO_MODE=1`, the default) ships well-known demo logins and
  generates an ephemeral session key. Never expose a demo-mode instance to an untrusted
  network.

## Running it more safely

- Set `LOGICWARD_DEMO_MODE=0` and provide strong `LOGICWARD_SECRET`, `LOGICWARD_TOKEN`,
  and `LOGICWARD_HMAC_KEY` (see `.env.example`). The app refuses to start otherwise.
- Bind services to `127.0.0.1` unless a split deployment requires otherwise.
- Keep the evidence log and signed baseline on storage only trusted operators can write.

## Reporting a vulnerability

This is a student/portfolio project. If you find a security issue, please open a GitHub
issue describing it (omit any sensitive details) or contact the maintainer. There is no
formal SLA.
