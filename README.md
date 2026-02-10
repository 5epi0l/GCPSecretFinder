# GCP Secret Manager Scanner

A Python tool for scanning Google Cloud Platform Secret Manager across all regions to discover and retrieve secrets. Useful for security audits, secret inventory, and cloud resource discovery.

## Features

- Scan all GCP regions for secrets in a single command
- Multiple authentication methods (access token, token file, or service account key)
- Optional secret value retrieval
- Export results to JSON
- Beautiful terminal UI with progress tracking
- Quiet mode for script integration

## Installation
```bash
git clone https://github.com/5epi0l/GCPSecretFinder.git
cd GCPSecretFinder
pip install -r requirements.txt
```

## Authentication

The tool supports three authentication methods:

### 1. Access Token (Direct)
```bash
python3 gcpsecretfinder.py --project my-project --token "ya29.c.b0Aaek..."
```

### 2. Access Token (From File)
```bash
python3 gcpsecretfinder.py --project my-project --token-file ~/token.txt
```

### 3. Service Account Key
```bash
python3 gcpsecretfinder.py --project my-project --service-account-key ~/key.json
```

## Usage Examples

### Basic Scanning

List all secrets across all regions:
```bash
python3 gcpsecretfinder.py --project gr-proj-8 --token-file ~/token.txt
```

### Retrieve Secret Values

Scan and retrieve the actual secret values:
```bash
python3 gcpsecretfinder.py --project my-project --token-file ~/token.txt --retrieve
```

### Retrieve Specific Version

Get a specific version of secrets instead of latest:
```bash
python3 gcpsecretfinder.py --project my-project \
  --token-file ~/token.txt \
  --retrieve \
  --version 2
```

## Command-Line Options
```
required arguments:
  -p, --project PROJECT         GCP project ID

authentication (one required):
  -t, --token TOKEN            Access token (String)
  -f, --token-file FILE        Path to file containing access token
  -s, --service-account-key    Path to service account key file

optional arguments:
  --retrieve                   Retrieve secret values (not just list them)
  --version VERSION            Secret version to retrieve (default: latest)
  -h, --help                   Show help message
```

## Supported Regions

The tool scans the following regions by default:

**Asia Pacific:**
- asia-east1, asia-east2
- asia-northeast1, asia-northeast2, asia-northeast3
- asia-south1, asia-south2
- asia-southeast1, asia-southeast2
- australia-southeast1, australia-southeast2

**Europe:**
- europe-central2
- europe-north1
- europe-west1, europe-west2, europe-west3, europe-west4, europe-west6

**Middle East:**
- me-central1, me-west1

**North America:**
- northamerica-northeast1, northamerica-northeast2
- us-central1
- us-east1, us-east4
- us-west1, us-west2, us-west3, us-west4

**South America:**
- southamerica-east1, southamerica-west1

## Output Format


### JSON Output

With `--retrieve`, secrets are retrieved in JSON format:
```json
[
  {
    "name": "projects/123456/secrets/api-key",
    "region": "us-east1",
    "value": "sk-abc123...",
    "version": "latest",
    "full_data": {
      "name": "projects/123456/secrets/api-key",
      "createTime": "2024-01-15T10:30:00Z",
      "labels": {},
      "replication": {
        "automatic": {}
      }
    }
  }
]
```

## Common Use Cases

### Security Audit
```bash
# Find all secrets and retrieve them
python3 gcpsecretfinder.py \
  --project prod-project \
  --service-account-key ~/audit-sa.json \
  --retrieve
```


### Secret Inventory
```bash
# List all secrets without retrieving values
python3 gcpsecretfinder.py \
  --project my-project \
  --token-file ~/token.txt \
```

### Integration with Other Tools
```bash
# Pipe to jq for filtering
python3 gcpsecretfinder.py \
  --project my-project \
  --token-file ~/token.txt \
  --retrieve \
  | jq '.[] | select(.name | contains("production"))'
```

## Permissions Required

The service account or user must have the following IAM permissions:

- `secretmanager.secrets.list` - To list secrets
- `secretmanager.versions.access` - To retrieve secret values (when using `--retrieve`)


## Error Handling

The tool handles common errors gracefully:
- Network timeouts (10 second timeout per request)
- Invalid credentials
- Missing permissions
- Non-existent regions
- Failed secret retrieval

Errors are logged to stderr while scanning continues for remaining regions.

## Performance Considerations

- Each region is scanned sequentially to avoid rate limiting
- Default timeout is 10 seconds per region
- Scanning all 31 regions typically takes 30-60 seconds
- Retrieval adds additional time proportional to number of secrets found


