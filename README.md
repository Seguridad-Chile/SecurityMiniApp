# SecurityMiniApp - Website Security Checker

A command-line tool written in Go to perform basic security checks on websites.

## Table of Contents

- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Compilation](#-compilation)
- [Usage](#-usage)
- [How It Works](#-how-it-works)
- [Technical Specifications](#-technical-specifications)
- [Interpreting Results](#-interpreting-results)
- [References](#-references)

---

## Features

- **HTTP/HTTPS Connection Check**: Verifies server response status
- **SSL/TLS Certificate Analysis**: Evaluates certificate security configuration
- **SSL Security Grade**: Assigns a grade from A+ to F based on configuration
- **Expiration Tracking**: Shows days remaining until certificate expiration
- **TLS Version Detection**: Identifies if outdated TLS versions are in use
- **Cipher Suite Verification**: Detects if strong or weak ciphers are used
- **Security Headers Check**: Analyzes the presence of important headers

### Security Headers Checked

| Header | Description |
|--------|-------------|
| HSTS | HTTP Strict Transport Security |
| CSP | Content Security Policy |
| X-Content-Type-Options | Prevents MIME type sniffing |
| X-Frame-Options | Clickjacking protection |
| X-XSS-Protection | Legacy anti-XSS protection |
| Referrer-Policy | Referrer information control |
| Permissions-Policy | Browser features control |

---

## Requirements

- **Go 1.16** or higher installed on the system
- **Operating system**: Windows, Linux, or macOS
- **Internet access** to perform the checks

---

## Installation

### Option 1: Download the executable (for Windows)

If you already have the `securityminiapp.exe` file, you can run it directly:

```powershell
.\securityminiapp.exe https://example.com
```

### Option 2: Compile from source

```powershell
# Navigate to the project directory
cd d:\www\wip\seguridadminiapp

# Compile the project
go build -o securityminiapp.exe
```

---

## Compilation

### Basic compilation

```powershell
go build -o securityminiapp.exe
```

### Cross-compilation for different operating systems

**Windows (64-bit):**
```powershell
GOOS=windows GOARCH=amd64 go build -o securityminiapp.exe
```

**Linux:**
```bash
GOOS=linux GOARCH=amd64 go build -o securityminiapp
```

**macOS:**
```bash
GOOS=darwin GOARCH=amd64 go build -o securityminiapp
```

### Compilation with optimization flags

```powershell
go build -ldflags="-s -w" -o securityminiapp.exe
```

---

## Usage

### Basic syntax

```powershell
securityminiapp.exe <url>
```

### Examples

**Check a site with https://**
```powershell
securityminiapp.exe https://google.com
```

**Check a site without specifying protocol**
```powershell
securityminiapp.exe example.com
```

**Check with specific port**
```powershell
securityminiapp.exe https://example.com:8443
```

---

## How It Works

### 1. HTTP Check

The program first attempts to connect to the server using Go's `net/http`:

```
Client.Get(url) → Receives status code and response headers
```

### 2. SSL/TLS Check

Establishes a direct TLS connection to port 443 to analyze the certificate:

```
tls.Dial("tcp", "host:443") → Extracts certificate information
```

### 3. Headers Analysis

Compares received headers against a list of recommended security headers.

### 4. Report Generation

Identifies issues and generates recommendations based on findings.

### Flow Diagram

```
┌─────────────────┐
│   Input URL     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ URL Validation  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ HTTP Connection │──────► Status Code
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ TLS Connection   │──────► Certificate Info
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Headers Analysis │──────► Security Headers
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Generate Report │
└─────────────────┘
```

---

## Technical Specifications

### Code Structure

```
securityminiapp/
├── main.go          # Main code
├── go.mod           # Go module file
├── go.sum           # Dependencies checksums
└── README.md        # This file
```

### Data Structures

**SecurityCheckResult:**
```go
type SecurityCheckResult struct {
    URL             string      // URL analyzed
    StatusCode      int         // HTTP status code
    SSLGrade        string      // SSL grade (A+ to F)
    SSLExpiryDays   int         // Days until expiration
    Headers         http.Header // Response headers
    SecurityIssues  []string    // Issues found
    Recommendations []string    // Recommendations
}
```

### SSL Grading Criteria

| Grade | Criteria |
|-------|----------|
| **A+** | TLS 1.3 + Strong cipher + Good curves |
| **A** | TLS 1.3 + Strong cipher |
| **B** | TLS 1.2 or higher |
| **F** | TLS 1.1 or lower |

### Strong Cipher Suites Detected

- TLS_AES_128_GCM_SHA256
- TLS_AES_256_GCM_SHA384
- TLS_CHACHA20_POLY1305_SHA256
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256

---

## Interpreting Results

### HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | ✅ Site accessible |
| 301/302 | ⚠️ Redirect (check for HTTPS redirect) |
| 403 | ⚠️ Access forbidden |
| 404 | ❌ Page not found |
| 5xx | ❌ Server error |

### Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| SSL expiring soon | Renew certificate before expiration date |
| Outdated TLS | Configure server to use TLS 1.2 or 1.3 |
| Weak cipher | Configure modern ciphers (AES-GCM, ChaCha20) |
| Missing headers | Add security headers in server configuration |

---

## Security and Privacy

- **No external dependencies**: Does not require third-party libraries to work
- **No data storage**: Does not save information about checked URLs
- **Read-only**: Only performs GET requests, does not modify anything on the server
- **Direct connection**: Does not use proxies or intermediaries

---

## References

- **Official Website**: [https://www.seg.cl](https://www.seg.cl)
- **Go Documentation**: [https://go.dev](https://go.dev)
- **OWASP Security Headers**: [https://owasp.org/www-project-secure-headers/](https://owasp.org/www-project-secure-headers/)
- **SSL Labs SSL Test**: [https://www.ssllabs.com/ssltest/](https://www.ssllabs.com/ssltest/)

For more information about web security and best practices, visit [https://www.seg.cl](https://www.seg.cl).

---

## License

This project is free to use and can be modified and distributed.

---

## Contributing

To contribute to the project:

1. Fork the repository
2. Create a branch for your feature (`git checkout -b feature/new-feature`)
3. Make your changes
4. Commit (`git commit -m 'Add new feature'`)
5. Push to the branch (`git push origin feature/new-feature`)
6. Open a Pull Request

---

## Contact

For questions or issues, create an issue in the project repository.