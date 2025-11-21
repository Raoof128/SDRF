# Security Policy

## 🔒 Supported Versions

We release patches for security vulnerabilities in the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## 🚨 Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: **security@secret-framework.io**

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

### What to Include in Your Report

Please include the following information in your report:

- **Type of vulnerability** (e.g., authentication bypass, injection, etc.)
- **Full paths of source file(s)** related to the vulnerability
- **Location of the affected source code** (tag/branch/commit or direct URL)
- **Step-by-step instructions** to reproduce the issue
- **Proof-of-concept or exploit code** (if possible)
- **Impact of the issue**, including how an attacker might exploit it
- **Your contact information** for follow-up

### What to Expect

After you submit a report, here's what will happen:

1. **Confirmation** - We'll acknowledge receipt within 48 hours
2. **Investigation** - We'll investigate and validate the issue within 5 business days
3. **Fix Development** - If confirmed, we'll work on a fix
4. **Disclosure Timeline** - We'll coordinate with you on the disclosure timeline
5. **Credit** - You'll be credited in our security advisory (if desired)

## 🛡️ Security Best Practices

### For Users

When using the Secret Detection & Rotation Framework:

1. **Secure Your Credentials**
   ```bash
   # Always use environment variables
   export GITHUB_TOKEN=ghp_xxxxxxxxxxxx
   export AWS_ACCESS_KEY_ID=AKIA...
   export AWS_SECRET_ACCESS_KEY=...
   
   # Never hard-code credentials in configuration files
   ```

2. **Rotate Credentials Regularly**
   ```bash
   # Set up automatic rotation
   secretctl rotate aws <key-id> --schedule monthly
   ```

3. **Use Least Privilege**
   - Grant minimum required permissions to service accounts
   - Use IAM roles instead of long-lived credentials when possible
   - Enable MFA on all accounts

4. **Secure the Framework Deployment**
   ```yaml
   # docker-compose.yml - Use secrets management
   services:
     api:
       secrets:
         - github_token
         - aws_credentials
   
   secrets:
     github_token:
       external: true
     aws_credentials:
       external: true
   ```

5. **Network Security**
   - Deploy API behind a reverse proxy (nginx, Traefik)
   - Use TLS/SSL for all communications
   - Implement rate limiting
   - Use API authentication (OAuth2, API keys)

6. **Audit Logs**
   ```bash
   # Enable comprehensive logging
   export ENABLE_AUDIT_LOGGING=true
   export AUDIT_LOG_PATH=/var/log/secret-framework/audit.log
   ```

### For Developers

When contributing to the framework:

1. **Never Commit Secrets**
   ```bash
   # Install pre-commit hooks
   pre-commit install
   
   # The hooks will catch secrets before commit
   ```

2. **Validate All Input**
   ```python
   from pydantic import BaseModel, validator
   
   class ScanRequest(BaseModel):
       repo_path: str
       
       @validator('repo_path')
       def validate_path(cls, v):
           if not Path(v).exists():
               raise ValueError('Repository path does not exist')
           return v
   ```

3. **Use Parameterized Queries**
   ```python
   # Good - prevents injection
   cursor.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
   
   # Bad - vulnerable to injection
   cursor.execute(f"SELECT * FROM findings WHERE id = {finding_id}")
   ```

4. **Implement Rate Limiting**
   ```python
   from fastapi import FastAPI, Depends
   from slowapi import Limiter, _rate_limit_exceeded_handler
   from slowapi.util import get_remote_address
   
   limiter = Limiter(key_func=get_remote_address)
   app = FastAPI()
   app.state.limiter = limiter
   
   @app.post("/scan/github")
   @limiter.limit("10/minute")
   async def scan_repository(request: Request):
       pass
   ```

5. **Secure Dependencies**
   ```bash
   # Regularly update dependencies
   pip install --upgrade -r requirements.txt
   
   # Check for vulnerabilities
   safety check
   bandit -r .
   ```

## 🔐 Security Features

### Built-in Security Controls

1. **Secret Masking**
   - All detected secrets are automatically masked in logs and reports
   - Only first and last 4 characters are shown

2. **Audit Logging**
   - All scan and rotation operations are logged
   - Includes timestamp, user, action, and result

3. **Encryption at Rest**
   - Reports can be encrypted using AES-256
   - Use encryption for sensitive scan results

4. **Access Control**
   - API endpoints support OAuth2 authentication
   - Role-based access control (RBAC) available
   - API key authentication for programmatic access

5. **Secure Rotation**
   - Credentials are rotated over secure channels (TLS)
   - Old credentials are immediately invalidated
   - New credentials are validated before deletion of old ones

### Security Scanning

We use multiple tools to ensure code security:

```bash
# Security linting
bandit -r . -f json -o bandit-report.json

# Dependency vulnerability scanning
safety check --json

# Static application security testing (SAST)
semgrep --config auto

# Secret scanning
secretctl scan local . --output json
```

## 🔍 Known Security Considerations

### 1. API Rate Limiting

**Issue**: Without rate limiting, the API could be subject to DoS attacks.

**Mitigation**: 
```python
# Implemented in api/server.py
from slowapi import Limiter
limiter = Limiter(key_func=get_remote_address)
```

### 2. Credential Storage

**Issue**: Temporary storage of credentials during rotation.

**Mitigation**:
- Credentials stored in memory only
- Immediately overwritten after use
- Never logged or persisted to disk

### 3. GitHub Token Permissions

**Issue**: GitHub tokens with excessive permissions.

**Mitigation**:
- Use fine-grained personal access tokens
- Request minimum required scopes
- Rotate tokens regularly

## 📋 Security Checklist

Before deploying to production:

- [ ] All credentials moved to environment variables
- [ ] TLS/SSL certificates configured
- [ ] API authentication enabled
- [ ] Rate limiting configured
- [ ] Audit logging enabled
- [ ] Dependencies updated and scanned
- [ ] Security headers configured (HSTS, CSP, etc.)
- [ ] Network firewall rules configured
- [ ] Backup and disaster recovery plan in place
- [ ] Security monitoring and alerting configured

## 🚀 Secure Deployment Example

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  api:
    image: secret-framework:1.0.0
    environment:
      - ENABLE_AUTH=true
      - ENABLE_RATE_LIMITING=true
      - ENABLE_AUDIT_LOGGING=true
    secrets:
      - github_token
      - aws_credentials
      - azure_credentials
    networks:
      - internal
    deploy:
      replicas: 3
      restart_policy:
        condition: on-failure

  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    networks:
      - internal
      - external

networks:
  internal:
    driver: overlay
  external:
    driver: overlay

secrets:
  github_token:
    external: true
  aws_credentials:
    external: true
  azure_credentials:
    external: true
```

## 📚 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Cloud Security Alliance](https://cloudsecurityalliance.org/)

## 🏆 Security Hall of Fame

We recognize and thank the following security researchers who have responsibly disclosed vulnerabilities:

*(This section will be updated as security researchers contribute)*

## 📞 Contact

For general security inquiries: security@secret-framework.io

For urgent security issues requiring immediate attention: urgent-security@secret-framework.io

---

**Last Updated**: 2024-01-15

Thank you for helping keep the Secret Detection & Rotation Framework and our users safe!
