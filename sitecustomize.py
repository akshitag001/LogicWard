"""Enable coverage measurement in subprocesses the smoke suites spawn.

Imported automatically at interpreter startup when this directory is on the path.
It only does anything when COVERAGE_PROCESS_START is set (i.e. during a CI
coverage run); otherwise it is a no-op, so normal runs are unaffected.
"""
try:  # pragma: no cover - startup shim
    import coverage

    coverage.process_startup()
except Exception:  # noqa: BLE001
    pass
