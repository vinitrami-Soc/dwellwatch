"""Shared helpers. Every test is offline; the real datasets come from datasets/fetch.sh."""

import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ATTACK_DATA = ROOT / "datasets" / "attack_data" / "datasets" / "attack_techniques"


def dataset(relative: str) -> Path:
    """A fetched attack_data file. Skips without it, unless CI says the datasets must be there."""
    path = ATTACK_DATA / relative
    if not path.is_file():
        message = f"{relative} not fetched; run datasets/fetch.sh"
        if os.environ.get("DWELLWATCH_REQUIRE_DATASETS"):
            pytest.fail(message)
        pytest.skip(message)
    return path


def process_event(command_line, image, *, original_file_name="", user="LAB\\jdoe", host="WS01.lab.local",
                  time="2025-04-24T09:00:00.0000000Z"):
    """A planted Sysmon process-creation event, flat, as load_events returns it."""
    return {
        "EventID": "1",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Computer": host,
        "TimeCreated": time,
        "Image": image,
        "OriginalFileName": original_file_name,
        "CommandLine": command_line,
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        "User": user,
    }
