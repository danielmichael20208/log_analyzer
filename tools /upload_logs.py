#!/usr/bin/env python3
"""
GitHub uploader for SIEM logs
Uploads data/logs_web.json to your portfolio repo
"""

import os
import json
import base64
import requests
from datetime import datetime


def push_logs_to_github():
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        print("[ERROR] GITHUB_TOKEN not set. Run: setx GITHUB_TOKEN \"TOKEN\" and restart PowerShell")
        return

    owner = "danielmichael20208"
    repo = "portfolio"   # <-- your dashboard repo
    path = "data/logs_web.json"

    local_path = os.path.join("data", "logs_web.json")
    if not os.path.exists(local_path):
        print("[WARN] No logs to upload")
        return

    with open(local_path, "r", encoding="utf-8") as f:
        content = f.read()

    # GitHub API requires Base64 encoding
    encoded = base64.b64encode(content.encode()).decode()

    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"

    # Check if file already exists (we need SHA to update)
    r = requests.get(url, headers={"Authorization": f"token {token}"})

    if r.status_code == 200:
        sha = r.json()["sha"]
    else:
        sha = None

    commit_msg = f"SIEM log update {datetime.utcnow().isoformat()}"

    payload = {
        "message": commit_msg,
        "content": encoded,
        "branch": "main"
    }

    if sha:
        payload["sha"] = sha

    r = requests.put(url, headers={"Authorization": f"token {token}"}, json=payload)

    if r.status_code in (200, 201):
        print("[UPLOAD] Logs updated successfully.")
    else:
        print("[ERROR] Upload failed:", r.text)
