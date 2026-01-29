#!/usr/bin/env python3
"""
Security Judge Script - Custom Data Security Validator

Validates security properties in code and data flows, correlating with 
research findings on data confidentiality, integrity, and authentication.

Checks for:
- Unencrypted sensitive data transmission
- Insecure cryptographic practices
- Authentication/authorization weaknesses  
- Data leak patterns from research
"""

import json
import os
import re
import sys
from typing import Dict, List, Tuple
from pathlib import Path
from datetime import datetime


class SecurityJudge:
    """Custom security validator based on research and best practices."""
    
    FINDINGS = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": []
    }
    
    # Patterns indicating potential security issues
    INSECURE_PATTERNS = {
        "plaintext_password": {
            "pattern": r"password\s*=\s*['\"][^'\"]*['\"]",
            "severity": "critical",
            "message": "Hardcoded password detected"
        },
        "plaintext_transmission": {
            "pattern": r"http://|\.send\(.*\)\s*#\s*no.*crypt",
            "severity": "high",
            "message": "Unencrypted data transmission detected"
        },
        "weak_crypto": {
            "pattern": r"DES|MD5|SHA1(?![0-9])|RC4",
            "severity": "high",
            "message": "Weak cryptographic algorithm detected"
        },
        "no_auth_check": {
            "pattern": r"def\s+(get|post|put|delete)\s*\([^)]*\):\s*#\s*(?!auth|check|verify)",
            "severity": "high",
            "message": "API endpoint lacks authentication validation"
        },
        "sql_injection_risk": {
            "pattern": r"execute\s*\(\s*['\"].*[\+%].*['\"]",
            "severity": "high",
            "message": "Potential SQL injection vulnerability"
        },
        "hard_coded_secret": {
            "pattern": r"(api_key|secret|token|password)\s*=\s*['\"][a-zA-Z0-9]{20,}['\"]",
            "severity": "critical",
            "message": "Hardcoded API key or secret detected"
        },
        "insecure_deserialization": {
            "pattern": r"pickle\.load|yaml\.load\s*\(|eval\s*\(|exec\s*\(",
            "severity": "critical",
            "message": "Unsafe deserialization/code execution detected"
        },
        "data_leak_logging": {
            "pattern": r"print\(.*(?:password|token|secret|api_key)",
            "severity": "high",
            "message": "Sensitive data logged/printed"
        },
        "missing_tls_verify": {
            "pattern": r"verify\s*=\s*False|ssl_verify\s*=\s*False|verify_ssl\s*=\s*False",
            "severity": "high",
            "message": "TLS/SSL verification disabled"
        },
        "weak_random": {
            "pattern": r"random\.choice|random\.randint|math\.random",
            "severity": "medium",
            "message": "Weak random number generation for security context"
        }
    }
    
    # Files/paths that should be encrypted or protected
    SENSITIVE_PATHS = [
        r"\.env", r"secrets\.yml", r"config\.prod\.json",
        r".*credentials.*", r".*private.*key.*", r".*token.*"
    ]
    
    def __init__(self):
        self.repo_path = Path(os.getenv("GITHUB_WORKSPACE", "."))
        self.commit_sha = os.getenv("COMMIT_SHA", "unknown")
        
    def scan_files(self) -> None:
        """Recursively scan all code files for security issues."""
        code_extensions = {'.py', '.js', '.ts', '.java', '.cpp', '.c', '.go', '.rb', '.php'}
        
        for filepath in self.repo_path.rglob('*'):
            if filepath.suffix in code_extensions and not self._is_excluded(filepath):
                self._scan_file(filepath)
    
    def _is_excluded(self, filepath: Path) -> bool:
        """Check if filepath should be excluded from scanning."""
        excluded = {'.git', '__pycache__', 'node_modules', '.venv', 'venv', 'dist', 'build'}
        return any(part in excluded for part in filepath.parts)
    
    def _scan_file(self, filepath: Path) -> None:
        """Scan individual file for security patterns."""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
            for pattern_name, pattern_config in self.INSECURE_PATTERNS.items():
                matches = list(re.finditer(
                    pattern_config['pattern'],
                    content,
                    re.IGNORECASE | re.MULTILINE
                ))
                
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    self._add_finding(
                        severity=pattern_config['severity'],
                        message=pattern_config['message'],
                        file=str(filepath.relative_to(self.repo_path)),
                        line=line_num,
                        snippet=lines[line_num - 1] if line_num <= len(lines) else ""
                    )
        
        except Exception as e:
            pass  # Skip files that can't be read
    
    def check_sensitive_files(self) -> None:
        """Verify sensitive files are properly protected."""
        for pattern in self.SENSITIVE_PATHS:
            for filepath in self.repo_path.rglob('*'):
                if re.search(pattern, filepath.name, re.IGNORECASE):
                    if not self._is_ignored(filepath):
                        self._add_finding(
                            severity="high",
                            message=f"Sensitive file {filepath.name} in repository",
                            file=str(filepath.relative_to(self.repo_path)),
                            line=0,
                            snippet="Add to .gitignore and use environment variables"
                        )
    
    def _is_ignored(self, filepath: Path) -> bool:
        """Check if file is in .gitignore."""
        gitignore_path = self.repo_path / '.gitignore'
        if gitignore_path.exists():
            with open(gitignore_path, 'r') as f:
                patterns = f.read().split('\n')
                for pattern in patterns:
                    if pattern.strip() and re.search(pattern, str(filepath)):
                        return True
        return False
    
    def validate_data_flows(self) -> None:
        """Validate secure data handling based on research."""
        for filepath in self.repo_path.rglob('*.py'):
            if self._is_excluded(filepath):
                continue
            
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Check for authenticated endpoints
                if 'def ' in content and '@app.route' in content:
                    routes = re.findall(
                        r'@app\.route\(["\']([^"\']+)["\'].*\).*?\ndef\s+(\w+)',
                        content,
                        re.DOTALL
                    )
                    
                    for route, func in routes:
                        if not any(check in content for check in ['authenticate', 'verify_token', '@auth']):
                            if route.startswith(('/api', '/user', '/data')):
                                self._add_finding(
                                    severity="high",
                                    message=f"API route {route} may lack authentication",
                                    file=str(filepath.relative_to(self.repo_path)),
                                    line=0,
                                    snippet=f"Ensure {func}() validates user identity"
                                )
            except:
                pass
    
    def _add_finding(self, severity: str, message: str, file: str, line: int, snippet: str) -> None:
        """Add a security finding to results."""
        finding = {
            "severity": severity,
            "message": message,
            "file": file,
            "line": line,
            "snippet": snippet.strip(),
            "timestamp": datetime.utcnow().isoformat()
        }
        self.FINDINGS[severity].append(finding)
    
    def generate_report(self) -> Dict:
        """Generate comprehensive security report."""
        total_findings = sum(len(v) for v in self.FINDINGS.values())
        
        report = {
            "scan_timestamp": datetime.utcnow().isoformat(),
            "commit_sha": self.commit_sha,
            "repository": os.getenv("GITHUB_REPO", "unknown"),
            "total_findings": total_findings,
            "critical": len(self.FINDINGS["critical"]),
            "high": len(self.FINDINGS["high"]),
            "medium": len(self.FINDINGS["medium"]),
            "low": len(self.FINDINGS["low"]),
            "findings": self.FINDINGS,
            "passed": total_findings == 0
        }
        
        return report
    
    def save_results(self, output_file: str = "judge-results.json") -> None:
        """Save security judge results to JSON."""
        report = self.generate_report()
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"Security judge results saved to {output_file}")
        print(f"\nSummary:")
        print(f"  Critical: {report['critical']}")
        print(f"  High:     {report['high']}")
        print(f"  Medium:   {report['medium']}")
        print(f"  Low:      {report['low']}")
        
        if not report['passed']:
            sys.exit(1)
    
    def run(self) -> None:
        """Execute full security validation."""
        print("🔍 Starting Security Judge Analysis...")
        print(f"📁 Scanning repository: {self.repo_path}")
        
        self.scan_files()
        self.check_sensitive_files()
        self.validate_data_flows()
        
        self.save_results()


if __name__ == "__main__":
    judge = SecurityJudge()
    judge.run()
