# 📡 API Documentation

## Secret Detection & Rotation Framework REST API

**Version:** 1.0.0  
**Base URL:** `http://localhost:8000`  
**OpenAPI Docs:** `http://localhost:8000/docs`  
**ReDoc:** `http://localhost:8000/redoc`  

---

## 🔐 Authentication

Currently, the API supports optional authentication. When enabled, use one of:

### Bearer Token
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:8000/scan/local
```

### API Key
```bash
curl -H "X-API-Key: YOUR_API_KEY" http://localhost:8000/scan/local
```

---

## 📍 Endpoints

### Health & Status

#### `GET /`
Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "service": "Secret Detection & Rotation Framework",
  "version": "1.0.0",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

---

### Scanning Endpoints

#### `POST /scan/local`
Scan a local Git repository for secrets.

**Request Body:**
```json
{
  "repo_path": "/path/to/repository",
  "scan_history": true,
  "max_commits": 100,
  "branch": "main"
}
```

**Parameters:**
- `repo_path` (string, required): Path to local Git repository
- `scan_history` (boolean, optional): Scan commit history (default: true)
- `max_commits` (integer, optional): Maximum commits to scan (default: 100)
- `branch` (string, optional): Specific branch to scan

**Response:**
```json
{
  "status": "completed",
  "findings_count": 42,
  "findings": [
    {
      "type": "aws.access_key",
      "value": "AKIA...AMPLE",
      "file": "config.py",
      "line": 10,
      "column": 20,
      "severity": "critical",
      "description": "AWS Access Key ID",
      "context": "...",
      "commit": "abc123",
      "author": "John Doe",
      "confidence": 0.95
    }
  ],
  "statistics": {
    "total_findings": 42,
    "by_severity": {
      "critical": 5,
      "high": 12,
      "medium": 20,
      "low": 5
    },
    "by_type": {
      "aws.access_key": 3,
      "github.pat": 2,
      "generic.high_entropy": 15
    }
  },
  "scan_time": 12.5,
  "report_path": "/reports/report_20240115.md"
}
```

**cURL Example:**
```bash
curl -X POST http://localhost:8000/scan/local \
  -H "Content-Type: application/json" \
  -d '{
    "repo_path": "/path/to/repo",
    "scan_history": true,
    "max_commits": 100
  }'
```

**Python Example:**
```python
import requests

response = requests.post(
    "http://localhost:8000/scan/local",
    json={
        "repo_path": "/path/to/repo",
        "scan_history": True,
        "max_commits": 100
    }
)

data = response.json()
print(f"Found {data['findings_count']} secrets")
```

---

#### `POST /scan/github`
Scan a GitHub repository for secrets.

**Request Body:**
```json
{
  "repo_name": "owner/repository",
  "scan_history": true,
  "scan_prs": true,
  "max_commits": 100,
  "max_prs": 50
}
```

**Parameters:**
- `repo_name` (string, required): Repository in format "owner/repo"
- `scan_history` (boolean, optional): Scan commit history (default: true)
- `scan_prs` (boolean, optional): Scan pull requests (default: true)
- `max_commits` (integer, optional): Maximum commits (default: 100)
- `max_prs` (integer, optional): Maximum PRs (default: 50)

**Response:** Same format as `/scan/local`

**cURL Example:**
```bash
curl -X POST http://localhost:8000/scan/github \
  -H "Content-Type: application/json" \
  -d '{
    "repo_name": "owner/repository",
    "scan_history": true,
    "scan_prs": true
  }'
```

---

#### `POST /scan/organization`
Scan an entire GitHub organization.

**Request Body:**
```json
{
  "org_name": "my-organization",
  "max_repos": 50,
  "scan_history": false
}
```

**Parameters:**
- `org_name` (string, required): GitHub organization name
- `max_repos` (integer, optional): Maximum repositories to scan (default: 50)
- `scan_history` (boolean, optional): Scan commit history (default: false)

**Response:**
```json
{
  "status": "completed",
  "organization": "my-organization",
  "repositories_scanned": 25,
  "total_findings": 158,
  "findings_by_repo": {
    "owner/repo1": [...],
    "owner/repo2": [...]
  },
  "scan_time": 245.8,
  "report_path": "/reports/org_scan_20240115.md"
}
```

---

### Rotation Endpoints

#### `POST /rotate/aws`
Rotate AWS IAM access keys.

**Request Body:**
```json
{
  "access_key_id": "AKIAIOSFODNN7EXAMPLE",
  "user_name": "john.doe"
}
```

**Parameters:**
- `access_key_id` (string, required): AWS access key ID to rotate
- `user_name` (string, optional): IAM user name (auto-detected if not provided)

**Response:**
```json
{
  "status": "completed",
  "success": true,
  "details": {
    "action": "rotate_iam_access_key",
    "access_key_id": "AKIAIOSFODNN7EXAMPLE",
    "user_name": "john.doe",
    "new_access_key_id": "AKIANEWKEY1234567890",
    "old_key_deactivated": true,
    "old_key_deleted": true,
    "secret_arn": "arn:aws:secretsmanager:us-east-1:...",
    "status": "success",
    "message": "Successfully rotated access key"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**cURL Example:**
```bash
curl -X POST http://localhost:8000/rotate/aws \
  -H "Content-Type: application/json" \
  -d '{
    "access_key_id": "AKIA...",
    "user_name": "john.doe"
  }'
```

---

#### `POST /rotate/azure`
Rotate Azure service principal secrets.

**Request Body:**
```json
{
  "service_principal_id": "12345678-1234-1234-1234-123456789012",
  "validity_days": 90
}
```

**Parameters:**
- `service_principal_id` (string, required): Service principal ID
- `validity_days` (integer, optional): Secret validity in days (default: 90)

**Response:**
```json
{
  "status": "completed",
  "success": true,
  "details": {
    "action": "rotate_service_principal_secret",
    "service_principal_id": "...",
    "app_id": "...",
    "display_name": "My App",
    "new_secret_expiry": "2024-04-15T10:30:00Z",
    "old_credentials_removed": 2,
    "keyvault_secret_name": "my-app-secret",
    "status": "success"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

---

#### `POST /rotate/github`
Rotate GitHub credentials.

**Request Body:**
```json
{
  "token_type": "pat",
  "token": "ghp_...",
  "repo_name": "owner/repo",
  "installation_id": 12345
}
```

**Parameters:**
- `token_type` (string, required): Type of token ("pat", "app", "deploy_key")
- `token` (string, optional): Token to rotate (for PAT)
- `repo_name` (string, optional): Repository (for deploy keys)
- `installation_id` (integer, optional): App installation ID

**Response:**
```json
{
  "status": "completed",
  "success": true,
  "details": {
    "action": "revoke_github_pat",
    "user": "username",
    "status": "partial",
    "message": "Token marked for revocation..."
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

---

### Report Endpoints

#### `GET /report/{report_id}`
Download a generated report.

**Parameters:**
- `report_id` (string, path parameter): Report identifier

**Response:** File download (Markdown/JSON/CSV/HTML)

**cURL Example:**
```bash
curl http://localhost:8000/report/report_20240115.md -o report.md
```

---

#### `GET /jobs`
List all scan jobs.

**Response:**
```json
{
  "jobs": {
    "job_123": {
      "status": "running",
      "target": "owner/repo",
      "started_at": "2024-01-15T10:30:00Z"
    }
  },
  "total": 1
}
```

---

#### `GET /jobs/{job_id}`
Get status of a specific scan job.

**Response:**
```json
{
  "job_id": "job_123",
  "status": "completed",
  "target": "owner/repo",
  "started_at": "2024-01-15T10:30:00Z",
  "completed_at": "2024-01-15T10:32:30Z",
  "findings": 42,
  "duration": 150.0
}
```

---

#### `POST /upload/scan`
Scan an uploaded file for secrets.

**Request:** multipart/form-data with file

**Response:**
```json
{
  "filename": "config.py",
  "findings_count": 3,
  "findings": [...]
}
```

**cURL Example:**
```bash
curl -X POST http://localhost:8000/upload/scan \
  -F "file=@config.py"
```

---

## ⚠️ Error Responses

### Standard Error Format

```json
{
  "detail": "Error message describing what went wrong",
  "status_code": 400,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### HTTP Status Codes

| Code | Meaning | Description |
|------|---------|-------------|
| 200 | Success | Request completed successfully |
| 400 | Bad Request | Invalid request parameters |
| 401 | Unauthorized | Authentication required |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 422 | Validation Error | Request validation failed |
| 429 | Rate Limit | Too many requests |
| 500 | Server Error | Internal server error |
| 503 | Service Unavailable | Service temporarily unavailable |

---

## 🚀 Rate Limiting

Default rate limits (configurable):
- **Scan endpoints:** 10 requests/minute
- **Rotation endpoints:** 5 requests/minute
- **Other endpoints:** 60 requests/minute

**Rate Limit Headers:**
```
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 8
X-RateLimit-Reset: 1642248600
```

---

## 🔧 SDK Examples

### Python SDK Usage

```python
import requests

class SecretFrameworkClient:
    """Client for Secret Detection API."""
    
    def __init__(self, base_url="http://localhost:8000", token=None):
        self.base_url = base_url
        self.token = token
        self.session = requests.Session()
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"
    
    def scan_local(self, repo_path, scan_history=True):
        """Scan local repository."""
        response = self.session.post(
            f"{self.base_url}/scan/local",
            json={
                "repo_path": repo_path,
                "scan_history": scan_history
            }
        )
        response.raise_for_status()
        return response.json()
    
    def rotate_aws(self, access_key_id, user_name=None):
        """Rotate AWS credentials."""
        response = self.session.post(
            f"{self.base_url}/rotate/aws",
            json={
                "access_key_id": access_key_id,
                "user_name": user_name
            }
        )
        response.raise_for_status()
        return response.json()

# Usage
client = SecretFrameworkClient()
results = client.scan_local("/path/to/repo")
print(f"Found {results['findings_count']} secrets")
```

### JavaScript/Node.js Usage

```javascript
const axios = require('axios');

class SecretFrameworkClient {
  constructor(baseURL = 'http://localhost:8000', token = null) {
    this.client = axios.create({
      baseURL,
      headers: token ? { 'Authorization': `Bearer ${token}` } : {}
    });
  }
  
  async scanLocal(repoPath, scanHistory = true) {
    const response = await this.client.post('/scan/local', {
      repo_path: repoPath,
      scan_history: scanHistory
    });
    return response.data;
  }
  
  async rotateAWS(accessKeyId, userName = null) {
    const response = await this.client.post('/rotate/aws', {
      access_key_id: accessKeyId,
      user_name: userName
    });
    return response.data;
  }
}

// Usage
const client = new SecretFrameworkClient();
const results = await client.scanLocal('/path/to/repo');
console.log(`Found ${results.findings_count} secrets`);
```

---

## 🔄 Webhooks

Configure webhooks to receive notifications when secrets are detected.

### Webhook Payload

```json
{
  "event": "secret_detected",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "repository": "owner/repo",
    "secret_type": "aws.access_key",
    "severity": "critical",
    "file_path": "config.py",
    "line_number": 10
  }
}
```

### Event Types
- `secret_detected` - New secret found
- `rotation_completed` - Credential rotation successful
- `rotation_failed` - Credential rotation failed
- `scan_completed` - Repository scan finished

---

## 📊 Pagination

For endpoints returning large datasets:

**Request:**
```
GET /findings?page=1&per_page=50
```

**Response:**
```json
{
  "data": [...],
  "pagination": {
    "page": 1,
    "per_page": 50,
    "total_items": 250,
    "total_pages": 5
  }
}
```

---

## 🎯 Best Practices

### 1. Error Handling
Always check status codes and handle errors gracefully:
```python
try:
    response = client.scan_local("/path/to/repo")
    if response['findings_count'] > 0:
        print(f"⚠️ Found {response['findings_count']} secrets")
except requests.exceptions.HTTPError as e:
    print(f"❌ API error: {e.response.json()['detail']}")
except Exception as e:
    print(f"❌ Unexpected error: {e}")
```

### 2. Async Operations
For long-running scans, use background jobs:
```python
# Start scan
response = client.post("/scan/github", json={...})
job_id = response.json()['job_id']

# Poll for completion
while True:
    status = client.get(f"/jobs/{job_id}").json()
    if status['status'] == 'completed':
        break
    time.sleep(5)
```

### 3. Batch Processing
For scanning multiple repositories:
```python
repos = ["owner/repo1", "owner/repo2", "owner/repo3"]

with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
    futures = [
        executor.submit(client.scan_github, repo)
        for repo in repos
    ]
    
    for future in concurrent.futures.as_completed(futures):
        result = future.result()
        print(f"Scan complete: {result['findings_count']} findings")
```

---

## 📝 OpenAPI Specification

The complete OpenAPI 3.0 specification is available at:
- **Interactive Docs:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc
- **JSON Spec:** http://localhost:8000/openapi.json

---

## 🐛 Troubleshooting

### Common Issues

**Issue:** 404 Repository not found
```
Solution: Verify repository path exists and is a valid Git repository
```

**Issue:** 401 Unauthorized
```
Solution: Provide valid GitHub token via GITHUB_TOKEN environment variable
```

**Issue:** 429 Rate Limit Exceeded
```
Solution: Wait for rate limit reset (check X-RateLimit-Reset header)
```

**Issue:** 500 Internal Server Error
```
Solution: Check API logs: docker-compose logs api
```

---

## 📞 Support

- **Documentation:** README.md
- **Issues:** GitHub Issues
- **Email:** api-support@secret-framework.io

---

**API Version:** 1.0.0  
**Last Updated:** 2024-01-15  
**Maintained by:** Security Engineering Team

