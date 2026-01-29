#!/usr/bin/env python3
"""Aggregate findings from all security scanning tools."""

import json
import os
from pathlib import Path
from typing import Dict, List
from collections import defaultdict


def aggregate_findings() -> Dict:
    """Aggregate all scan results from artifacts."""
    
    findings_by_tool = defaultdict(list)
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    
    artifact_dir = Path(".")
    
    # Parse CodeQL results
    for codeql_file in artifact_dir.glob("codeql-results-*/results.sarif"):
        try:
            with open(codeql_file) as f:
                data = json.load(f)
                for run in data.get("runs", []):
                    for result in run.get("results", []):
                        findings_by_tool["CodeQL"].append({
                            "message": result.get("message", {}).get("text", ""),
                            "severity": "high",
                            "rule": result.get("ruleId", "")
                        })
                        severity_counts["high"] += 1
        except:
            pass
    
    # Parse Trufflehog results
    trufflehog_file = Path("trufflehog-results/trufflehog-results.json")
    if trufflehog_file.exists():
        try:
            with open(trufflehog_file) as f:
                for line in f:
                    try:
                        result = json.loads(line)
                        findings_by_tool["Trufflehog"].append({
                            "message": f"Secret detected: {result.get('detectorName', '')}",
                            "severity": "critical",
                            "path": result.get("filePath", "")
                        })
                        severity_counts["critical"] += 1
                    except:
                        pass
        except:
            pass
    
    # Parse Snyk results
    snyk_file = Path("snyk-results/snyk-results.json")
    if snyk_file.exists():
        try:
            with open(snyk_file) as f:
                data = json.load(f)
                for vuln in data.get("vulnerabilities", []):
                    sev = vuln.get("severity", "medium").lower()
                    findings_by_tool["Snyk"].append({
                        "message": vuln.get("title", ""),
                        "severity": sev,
                        "package": vuln.get("packageName", "")
                    })
                    if sev in severity_counts:
                        severity_counts[sev] += 1
        except:
            pass
    
    # Parse Checkov results
    checkov_file = Path("checkov-results/checkov-results.json")
    if checkov_file.exists():
        try:
            with open(checkov_file) as f:
                data = json.load(f)
                for failed_check in data.get("failed_checks", []):
                    sev = "high" if "failed" in str(failed_check) else "medium"
                    findings_by_tool["Checkov"].append({
                        "message": failed_check.get("check_id", ""),
                        "severity": sev,
                        "file": failed_check.get("file_path", "")
                    })
                    severity_counts[sev] += 1
        except:
            pass
    
    # Parse Judge Script results
    judge_file = Path("judge-script-results/judge-results.json")
    if judge_file.exists():
        try:
            with open(judge_file) as f:
                data = json.load(f)
                for sev_level in ["critical", "high", "medium", "low"]:
                    for finding in data.get("findings", {}).get(sev_level, []):
                        findings_by_tool["SecurityJudge"].append({
                            "message": finding.get("message", ""),
                            "severity": sev_level,
                            "file": finding.get("file", "")
                        })
                        severity_counts[sev_level] += len(data.get("findings", {}).get(sev_level, []))
        except:
            pass
    
    # Parse ZAP results
    zap_file = Path("zap-api-results/zap-results.json")
    if zap_file.exists():
        try:
            with open(zap_file) as f:
                data = json.load(f)
                for alert in data.get("site", [{}])[0].get("alerts", []):
                    sev_map = {"High": "high", "Medium": "medium", "Low": "low"}
                    sev = sev_map.get(alert.get("riskcode", "1"), "medium")
                    findings_by_tool["OWASP ZAP"].append({
                        "message": alert.get("name", ""),
                        "severity": sev,
                        "url": alert.get("instances", [{}])[0].get("uri", "")
                    })
                    severity_counts[sev] += 1
        except:
            pass
    
    # Generate summary
    summary = f"""
### Security Scan Summary

**Total Findings:** {sum(severity_counts.values())}

- 🔴 **Critical:** {severity_counts['critical']}
- 🟠 **High:** {severity_counts['high']}
- 🟡 **Medium:** {severity_counts['medium']}
- 🔵 **Low:** {severity_counts['low']}

### Tools Executed
"""
    
    for tool in sorted(findings_by_tool.keys()):
        count = len(findings_by_tool[tool])
        summary += f"\n- **{tool}:** {count} findings"
    
    aggregated = {
        "timestamp": str(Path(".")),
        "summary": summary,
        "total_findings": sum(severity_counts.values()),
        "severity_breakdown": severity_counts,
        "findings_by_tool": dict(findings_by_tool),
        "scan_passed": severity_counts["critical"] == 0
    }
    
    return aggregated


if __name__ == "__main__":
    results = aggregate_findings()
    
    with open("aggregated-findings.json", "w") as f:
        json.dump(results, f, indent=2)
    
    with open("security-summary.txt", "w") as f:
        f.write(results["summary"])
    
    print(results["summary"])
