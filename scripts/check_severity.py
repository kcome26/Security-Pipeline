#!/usr/bin/env python3
"""Check severity levels and exit with appropriate code."""

import json
import sys
from pathlib import Path


def check_severity(severity_level: str) -> int:
    """Count findings of a given severity level."""
    
    try:
        with open("aggregated-findings.json") as f:
            data = json.load(f)
            return data.get("severity_breakdown", {}).get(severity_level, 0)
    except:
        return 0


if __name__ == "__main__":
    if len(sys.argv) > 1:
        severity = sys.argv[1]
        count = check_severity(severity)
        print(count)
        sys.exit(0 if count == 0 else 1)
    else:
        print("Usage: check_severity.py <severity>")
        sys.exit(1)
