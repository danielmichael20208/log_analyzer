import json
import os
from datetime import datetime

LOG_FILE = os.path.join(os.path.dirname(__file__), "../data/logs_web.json")


def log_event(source, level, event_type, message, component=None, context=None, timestamp=None):
    """
    Local structured SIEM logging used by all tools before upload.
    """
    event = {
        "timestamp": timestamp or datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "source": source.upper(),
        "level": level.upper(),
        "event_type": event_type,
        "message": message
    }

    if component:
        event["component"] = component

    if context:
        event["context"] = context

    # Read existing logs
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            logs = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        logs = []

    logs.append(event)

    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2)

    return event
