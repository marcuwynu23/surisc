<div align="center">
  <h1>surisc</h1>

  ![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)
  ![Security](https://img.shields.io/badge/Security-Reconnaissance-red?style=flat)
  ![Status](https://img.shields.io/badge/Status-Active-success?style=flat)

  <p><strong>A high-performance reconnaissance tool built specifically for frontend web security.</strong></p>
</div>

Written in Go, it operates entirely in memory to scrape, parse, and analyze JavaScript bundles from target URLs, proactively hunting for leaked API keys, hardcoded credentials, and exposed environment variables.

## Features

- **Memory-Resident Scraping**: Operates entirely in RAM using `colly/v2` to intercept target URLs, discover `<script>` tags, and fetch payload contents without writing temporary files to disk.
- **Concurrent Engine**: Utilizes goroutines and `sync.WaitGroup` to process multiple Javascript bundles concurrently.
- **Shannon Entropy Analysis**: Scans alphanumeric strings to calculate true information density (`H = - sum(p * log2(p))`), allowing the scanner to flag complex payloads such as JWTs or generic cloud provider keys.
- **Pattern Matching**: Contains built-in rules designed to detect:
  - AWS Access Keys (`AKIA...`)
  - Stripe Secret Keys (`sk_live_...`)
  - GitHub Personal Access Tokens (`ghp_...`)
  - GitLab Personal Access Tokens (`glpat-...`)
  - Mail Service API Keys (SendGrid, Mailgun)
  - Payment & Gateway Tokens (Square, Twilio)
  - RSA Private Keys headers (`-----BEGIN PRIVATE KEY...`)
  - Slack API Tokens (`xoxb-...`)
  - Google Firebase API Keys
  - Exposed map file dependencies (`.map`)
  - `Bearer` authentication tokens
  - Internal IP address ranges (`10.x`, `172.16.x`, `192.168.x`)
  - Build-time `import.meta` asset leaks
  - Generic secret strings and variable assignments (e.g., `API_KEY:"value"`)
- **False Positive Filtering**: Automatically ignores standard frontend compilation artifacts such as the Base64 sequence dictionary, WebAssembly module headers, and standard React.js validation warnings.

## Build Instructions

Use the included `Makefile` to securely compile SuriSC.

```sh
# Compile the executable into /dist/surisc.exe
make all

# Clean previous build outputs
make clean

# Run Unit and E2E verification tests
make test
```

## Usage

SuriSC can be executed directly from the terminal and supports both raw console output and JSON rendering.

### Basic Reconnaissance Scan
```sh
.\dist\surisc.exe -u https://example.com
```

### JSON Reporting Mode
```sh
.\dist\surisc.exe -u https://example.com -o json
```

### Output Example
```text
SuriSC Completed. Results:
--------------------------------------------------------------------------------
[!]     [FIREBASE_API_KEY]
        [SOURCE_URL]: https://example.com/assets/index.js
        [GRAVITY_SCORE]: 9.00
        [SNIPPET]: AIzaSyBLT...
--------------------------------------------------------------------------------
[!]     [IMPORT_META_LEAK]
        [SOURCE_URL]: https://example.com/assets/index.js
        [GRAVITY_SCORE]: 8.50
        [SNIPPET]: import.meta.env.VITE_BACKEND_API
--------------------------------------------------------------------------------
```

## Docker and Podman Usage

SuriSC can be built and run in a container environment using either Docker or Podman.

### Building the Image

Using **Docker**:
```sh
docker build -t surisc .
```

Using **Podman**:
```sh
podman build -t surisc .
```

### Running the Container

Once built, you can run the container by passing your target URL using the `-u` flag.

Using **Docker**:
```sh
docker run --rm surisc -u https://example.com
```
For JSON output:
```sh
docker run --rm surisc -u https://example.com -o json
```

Using **Podman**:
```sh
podman run --rm surisc -u https://example.com
```
For JSON output:
```sh
podman run --rm surisc -u https://example.com -o json
```
