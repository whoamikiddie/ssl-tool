
# SSL Certificate Tool

## Overview

The SSL Certificate Tool (`sslinfo`) is a command-line utility for fetching SSL certificate information from a specified domain. It provides details about the SSL certificate, including the protocol, cipher suite, subject, issuer, validity period, and more. The tool also allows you to export the fetched information to a file in either text or JSON format.

## Features

- Fetch SSL certificate information from a specified domain.
- Display certificate details in the console.
- Export certificate information to a file in text or JSON format.
- Option to verify the SSL certificate.
- Configurable timeout for connection attempts.

## Requirements

- Go 1.16 or higher

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/whoamikiddie/ssl-tool.git
   ```

2. Change into the directory:

   ```bash
   cd ssl-tool
   ```

3. Build the application:

   ```bash
   go mod init
   go mod tidy
   go build -o ssl-tool
   ```

## Usage

To run the tool, use the following command:

```bash
./ssl-tool --domain <your-domain> --output <output-file-path> [options]
```

### Flags

- `--domain`, `-d`: (Required) The domain to fetch SSL information from.
- `--output`, `-o`: (Required) The path where the output file will be saved.
- `--timeout`, `-t`: (Optional) Duration for the connection timeout (default: `5s`).
- `--verify`: (Optional) Flag to verify the SSL certificate (default: `false`).

### Example

```bash
./ssl-tool --domain example.com --output certificate_info.json --timeout 10s --verify
```

## Output

The output file will contain the following information about the SSL certificate:

- Protocol
- Cipher Suite
- Subject
- Issuer
- Version
- Serial Number
- Not Before
- Not After
- Key Length
- Signature Algorithm
- Certificate Chain (if applicable)

### Example Output Format

**Text Format:**
```
Protocol: TLS 1.2
Cipher:
  └╴0: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
Subject:
  └╴CN: example.com
Issuer:
  └╴CN: Let's Encrypt Authority X3
Version: 3
Serial Number: 1234567890
Not Before: Fri, 01 Jan 2021 00:00:00 UTC
Not After: Mon, 01 Jan 2022 00:00:00 UTC
Key Length: 2048 bits
Signature Algorithm: sha256WithRSAEncryption
```

**JSON Format:**
```json
{
  "protocol": "TLS 1.2",
  "cipher": 0x1301,
  "subject": {
    "CN": "example.com"
  },
  "issuer": {
    "CN": "Let's Encrypt Authority X3"
  },
  "version": "3",
  "serialNumber": "1234567890",
  "notBefore": "Fri, 01 Jan 2021 00:00:00 UTC",
  "notAfter": "Mon, 01 Jan 2022 00:00:00 UTC",
  "keyLength": 2048,
  "signatureAlgorithm": "sha256WithRSAEncryption",
  "chain": []
}
```
