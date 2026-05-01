#!/usr/bin/env python3
"""
Merge-upload SIEM logs to portfolio repo.
Downloads the portfolio existing data/logs_web.json, appends any new
local events (deduplicated by timestamp+source), then pushes back.
"""

import os
import json
import base64
import requests
from datetime import datetime

OWNER      = "danielmichael20208"
REPO       = "portfolio"
PATH       = "data/logs_web.json"
API_URL    = f"https://api.github.com/repos/{OWNER}/{REPO}/contents/{PATH}"
MAX_EVENTS = 500


def push_logs_to_github():
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        print("[UPLOAD] GITHUB_TOKEN not set — skipping upload.")
        print("[UPLOAD] Set it with:  setx GITHUB_TOKEN \"your_token\"  then restart your terminal.")
        return

    local_path = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "data", "logs_web.json")
    )
    if not os.path.exists(local_path):
        print("[UPLOAD] No local log file found — skipping.")
        return

    try:
        with open(local_path, "r", encoding="utf-8") as f:
            local_events = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"[UPLOAD] Could not read local log file: {e}")
        return

    if not local_events:
        print("[UPLOAD] No local events to upload.")
        return

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    r = requests.get(API_URL, headers=headers, timeout=10)
    existing_events = []
    sha = None

    if r.status_code == 200:
        data = r.json()
        sha = data["sha"]
        try:
            raw = base64.b64decode(data["content"]).decode("utf-8")
            existing_events = json.loads(raw)
        except Exception:
            existing_events = []
    elif r.status_code != 404:
        print(f"[UPLOAD] Could not fetch existing portfolio log: HTTP {r.status_code}")
        return

    seen = {(e.get("timestamp", ""), e.get("source", "")) for e in existing_events}
    new_events = [
        e for e in local_events
        if (e.get("timestamp", ""), e.get("source", "")) not in seen
    ]

    merged = existing_events + new_events
    if len(merged) > MAX_EVENTS:
        merged = merged[-MAX_EVENTS:]

    content_b64 = base64.b64encode(
        json.dumps(merged, indent=2).encode("utf-8")
    ).decode("utf-8")

    payload = {
        "message": f"SIEM log update {datetime.utcnow().isoformat()}Z",
        "content": content_b64,
        "branch": "main",
    }
    if sha:
        payload["sha"] = sha

    r = requests.put(API_URL, headers=headers, json=payload, timeout=15)
    if r.status_code in (200, 201):
        print(f"[UPLOAD] Pushed {len(new_events)} new event(s) — {len(merged)} total in portfolio.")
    else:
        msg = r.json().get("message", r.text[:200])
        print(f"[UPLOAD] Failed: HTTP {r.status_code} — {msg}")
