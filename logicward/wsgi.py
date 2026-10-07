"""Production WSGI entrypoint (Prompt 2.6).

The built-in Flask dev server is fine for the demo, but for a longer-lived
deployment serve this module with a real WSGI server:

    # Windows-friendly:
    waitress-serve --listen=127.0.0.1:8080 logicward.wsgi:app

    # Linux:
    gunicorn -w 1 -b 127.0.0.1:8080 logicward.wsgi:app

Use a single worker (`-w 1`): the drift engine, event bus, and in-process plant
are per-process singletons, so multiple workers would each run their own copy.
"""
from __future__ import annotations

from logicward.dashboard.app import create_app

app = create_app()
