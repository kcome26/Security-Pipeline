# Comprehensive Security Pipeline

A production-grade GitHub Actions security scanning pipeline integrating SAST, DAST, IaC scanning, dependency auditing, secret detection, and custom data security validation. Fully parallelized for rapid security feedback.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Push / Pull Request Trigger                   │
└────────────────────┬────────────────────────────────────────────┘
                     │
        ┌────────────┴────────────┬───────────┬──────────────┐
        │                         │           │              │
    ┌───▼────┐  ┌──────────┐  ┌──▼─────┐  ┌─▼──────┐  ┌───▼────┐
    │CodeQL  │  │Trufflehog│  │Checkov │  │ Snyk   │  │MobSF   │
    │(SAST)  │  │(Secrets) │  │(IaC)   │  │(Deps)  │  │(Mobile)│
    └────┬───┘  └────┬─────┘  └───┬────┘  └──┬─────┘  └───┬────┘
         │           │            │         │         │
    ┌────▼───┐  ┌────▼─────┐  ┌───▼────┐  ┌──▼─────┐  ┌───▼────┐
    │Judge   │  │OWASP ZAP │  │Result  │  │Artifact│  │Status  │
    │Script  │  │API Scan  │  │Aggreg  │  │Upload  │  │Gate    │
    └────┬───┘  └────┬─────┘  └───┬────┘  └──┬─────┘  └───┬────┘
         │           │            │         │         │
         └───────────┴────────────┴─────────┴─────────┘
                     │
        ┌────────────▼────────────┐
        │ PR Comment / Report     │
        │ (if failures/critical)  │
        └────────────┬────────────┘
                     │
        ┌────────────▼────────────┐
        │ Pipeline Pass/Fail Gate │
        └────────────────────────┘
```

## Security Tools Integrated

### Static Application Security Testing (SAST)
- **CodeQL**: Multi-language semantic code analysis for vulnerable patterns, injection flaws, and logic bugs
- **Checkov**: Infrastructure-as-Code scanning for Terraform misconfigurations (exposed credentials, insecure permissions, etc.)

### Dynamic Application Security Testing (DAST)
- **OWASP ZAP**: API security testing including authentication bypass, injection vulnerabilities, and insecure data handling
- **MobSF**: Mobile application security framework for APK/IPA analysis (cloud-hosted on AWS)

### Dependency & Secret Scanning
- **Snyk**: Third-party library vulnerability auditing with automated remediation suggestions
- **Trufflehog**: High-entropy secret detection (API keys, tokens, credentials) across entire repository

### Custom Validation
- **Security Judge Script**: Python-based validator checking for:
  - Hardcoded credentials and weak cryptography
  - Unencrypted data transmission patterns
  - Authentication/authorization weaknesses in API endpoints
  - Insecure deserialization and code execution functions
  - TLS verification bypass attempts

## Setup & Configuration

### Prerequisites
- GitHub repository with Actions enabled
- AWS account (for MobSF cloud hosting)
- API keys for Snyk, MobSF (stored as GitHub Secrets)

### GitHub Secrets Required
```
SNYK_TOKEN              # Snyk API token
MOBSF_API_KEY           # MobSF API authentication key
MOBSF_API_URL           # MobSF cloud instance URL (e.g., http://mobsf.example.com)
```

### Deployment

1. **Local Testing**
   ```bash
   docker-compose up -d mobsf
   python3 scripts/security_judge.py
   ```

2. **Cloud Infrastructure (Terraform)**
   ```bash
   cd terraform/
   terraform init
   terraform plan
   terraform apply -var="key_name=your-key-pair"
   ```

3. **GitHub Actions Integration**
   - Copy `.github/workflows/security-pipeline.yml` to your repository
   - Add secrets to GitHub repository settings
   - Push code to trigger pipeline

## Parallelization & Performance

All security scanning jobs execute **simultaneously**:
- **CodeQL** language matrix parallelization (C++, Java, Python, etc.)
- **SAST/DAST/IaC/Dependency scanning** run independently
- **Aggregation** waits for all parallel jobs before generating report
- **Total runtime**: ~30-120 seconds depending on code size and cloud latency

## Artifact Output

Each scanning tool generates JSON/SARIF reports:
```
artifacts/
├── codeql-results-*/
│   └── results.sarif
├── trufflehog-results.json
├── snyk-results.json
├── checkov-results.json
├── judge-results.json
├── zap-api-results/
│   ├── zap-api-report.html
│   └── zap-results.json
└── security-report/
    ├── aggregated-findings.json
    └── security-summary.txt
```

## Custom Judge Script

The Security Judge script (`scripts/security_judge.py`) validates data security properties:

### Detections
- **Plaintext Passwords**: `password = "..."` (critical)
- **Weak Cryptography**: MD5, DES, SHA1 usage (high)
- **Unencrypted Transmission**: HTTP without encryption (high)
- **Missing Auth**: API routes without authentication checks (high)
- **SQL Injection Risk**: Dynamic query construction (high)
- **Hardcoded Secrets**: API keys in source (critical)
- **Unsafe Deserialization**: `pickle.load`, `yaml.load`, `eval()` (critical)
- **Data Leakage**: Sensitive info in logs/print statements (high)
- **Disabled TLS Verification**: `verify=False` (high)

### Usage
```python
from scripts.security_judge import SecurityJudge

judge = SecurityJudge()
judge.run()  # Outputs judge-results.json
```

## Result Aggregation & Gating

The pipeline aggregates findings from all tools:
- **Critical** findings trigger pipeline failure
- **High** severity findings logged for review
- **PR comments** automatically posted with summary
- **Severity breakdown** tracked over time

### Sample PR Comment
```
## 🔒 Security Scan Results

**Total Findings:** 5

- 🔴 **Critical:** 0
- 🟠 **High:** 2 (CodeQL: 1, OWASP ZAP: 1)
- 🟡 **Medium:** 2 (Checkov: 1, Snyk: 1)
- 🔵 **Low:** 1 (Judge Script: 1)

### Tools Executed
- **CodeQL:** 1 findings
- **OWASP ZAP:** 1 findings
- **Checkov:** 1 findings
- **Snyk:** 1 findings
- **Judge Script:** 1 findings
```

## Technologies & Skills Demonstrated

- **SAST/DAST**: CodeQL, OWASP ZAP, MobSF, Checkov
- **CI/CD**: GitHub Actions workflow orchestration & parallelization
- **Cloud Infrastructure**: AWS EC2, Terraform IaC
- **Container Orchestration**: Docker, Docker Compose
- **Custom Tooling**: Python security validation framework
- **Security Research**: Data security validation tied to authentication/encryption weaknesses
- **API Security**: HTTP/REST API testing and validation
- **Secret Management**: GitHub Secrets for credential handling

## Future Enhancements

- [ ] Integration with Snyk AI for automated remediation
- [ ] Machine learning for anomaly detection in security patterns
- [ ] Kubernetes deployment for scalable MobSF instances
- [ ] SBOM (Software Bill of Materials) generation
- [ ] Historical trend analysis and reporting dashboard
- [ ] Jira/Slack notification integration

## License
MIT

---

**Author**: Kendall Comeaux | **Contact**: kendalljcomeaux@gmail.com
