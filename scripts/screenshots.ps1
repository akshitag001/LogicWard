# Regenerate the UI screenshots, demo GIF, and code snapshots (Prompt 5.1/5.2).
# One-time: pip install -e ".[dev]" ; playwright install chromium ; (ffmpeg on PATH for the GIF)
$ErrorActionPreference = "Stop"
python scripts/capture_screenshots.py
python scripts/code_snapshots.py
