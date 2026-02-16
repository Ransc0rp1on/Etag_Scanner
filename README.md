# ETag Analyzer
A powerful Python tool for analyzing ETag headers to detect information disclosure vulnerabilities and fingerprint web servers.

## 📋 Description
ETag Analyzer is a security testing tool that examines ETag headers returned by web servers to identify potential information disclosure vulnerabilities. It can decode various ETag formats (Apache, Nginx, IIS), detect leaked filesystem metadata (inodes, file sizes, modification times), and perform conditional request tests.

## ✨ Features
Format Detection
Automatically identifies ETag formats:

Apache (hex/decimal) - inode-size-mtime

Nginx - hex hashes (MD5, SHA1, SHA256)

IIS/ASP.NET - timestamp:changeNumber

## Information Disclosure Detection
🔴 Critical: Inode numbers leaked (Apache-style)

🟡 Medium: File sizes exposed

🟢 Low: Timestamps and modification times

## Security Tests
Conditional requests (If-None-Match, If-Match)

Compression effect analysis (gzip)

Range request testing

Content hash comparison

Additional Features
Server fingerprinting

Custom request delays

Comprehensive output formatting

Nessus-style vulnerability reporting

## 🚀 Installation
```
# Clone the repository
git clone https://github.com/yourusername/etag-analyzer.git
```
```
# Navigate to directory
cd etag-analyzer
```

### Install dependencies
```
pip install requests
```
##📖 Usage
Basic Usage
```
python3 Etag_ext.py https://example.com/file.js
```
Command Line Options
Option	Description
url	Target URL (required)
```
--conditional	Run conditional request tests (If-None-Match, If-Match)
--compression	Test ETag with Accept-Encoding: gzip
--range	Test ETag with Range request
--no-hash	Skip content download & hash comparison
--full	Run all tests (conditional, compression, range)
--delay	Seconds between requests (default: 0.5)
```
##Examples
Basic Analysis
```
python3 Etag_ext.py https://example.com/styles.css
```
Full Security Assessment

```
python3 Etag_ext.py https://example.com/api/data --full
```
Specific Tests with Custom Delay
```
python3 Etag_ext.py https://example.com/image.jpg --conditional --range --delay 1
```
Skip Content Hashing for Large Files
```
python3 Etag_ext.py https://example.com/video.mp4 --no-hash
```
##📊 Output Examples
Apache Information Disclosure
```
=== ETag Analysis for https://example.com/file.txt ===

[+] Server: Apache/2.4.41
[+] Raw ETag: "7a3f-1e4a-5b8c2d1f"
[+] Weak: False
[+] Stripped value: 7a3f-1e4a-5b8c2d1f

[ ETAG FORMAT ANALYSIS ]
[*] Detected format: Apache (hex)
[*] Decoded components:
    - inode: 31295
    - size: 7754
    - mtime_hex: 5b8c2d1f
[*] Human readable:
    - size: 7754 bytes (7.57 KB)
    - mtime: 2023-09-15 14:23:45 UTC
    - inode: 31295

[!] SECURITY WARNING: INFORMATION DISCLOSURE DETECTED [!]
    The server is leaking internal filesystem metadata via the ETag header.
    
    Disclosed Information:
      - Inode number  : 31295
      - File size     : 7754 bytes (7.57 KB)
      - Modified time : 2023-09-15 14:23:45 UTC
    
    Potential Impact: Inode numbers can aid in fingerprinting the filesystem
    and may be used in targeted attacks. File sizes and modification times
    reveal non-public information about the resource.

    Server identifies as Apache – this is a known configuration weakness.
```
###Nginx Hash Format
```
[ ETAG FORMAT ANALYSIS ]
[*] Detected format: Nginx-style hex hash
[*] Decoded components:
    - hash: 5d41402abc4b2a76b9719d911017c592
[*] Human readable:
    - hash: 5d41402abc4b2a76b9719d911017c592
    - hint: Possible MD5

[ CONTENT HASH COMPARISON ]
[+] Content length: 12345 bytes
[+] MD5: 5d41402abc4b2a76b9719d911017c592
[+] SHA1: d0f2ff9eea6b2a8c...
[+] SHA256: 9c8c5c5d5e5f5g5h...
[+] ETag matches MD5 of content

```
###IIS/ASP.NET Format
```
[ ETAG FORMAT ANALYSIS ]
[*] Detected format: IIS/ASP.NET
[*] Decoded components:
    - timestamp_hex: 5f8d9e1a
    - changeNumber_hex: 3b7a
[*] Human readable:
    - changeNumber: 15226
    - timestamp: 2023-10-18 09:23:45 UTC

[*] Information Disclosure (Low Severity):
    The ETag contains a timestamp (IIS/ASP.NET style).
      - Timestamp : 2023-10-18 09:23:45 UTC
    This reveals the approximate generation time of the response.
```
###Conditional Request Tests
```
[ CONDITIONAL REQUEST TESTS ]
[+] If-None-Match with strong ETag: 304 Not Modified (expected)
[+] If-Match with strong ETag: 200 OK (expected)
Compression Test

[ COMPRESSION TEST ]
[+] Content-Encoding: gzip
[+] ETag with gzip: "7a3f-1e4a-5b8c2d1f"
[+] ETag unchanged with compression
Range Request Test
text
[ RANGE REQUEST TEST ]
[+] Range request successful (206 Partial Content)
[+] Received 100 bytes
[+] First 100 bytes MD5: 9e107d9d372bb6826bd81d3542a419d6

```
## 🔒 Security Implications
High Severity (Apache-style)
Inode numbers: Can be used for filesystem fingerprinting and targeted attacks

File sizes: Reveal non-public information about resources

Modification times: Expose content update patterns

Medium Severity
Content hashes: May reveal if content is identical across different paths

Low Severity (IIS-style)
Timestamps: Reveal approximate generation time of responses

##🛠️ How It Works
Analysis Flow
Initial Request: Sends HEAD request to retrieve ETag and Server headers

ETag Parsing: Strips weak validators and quotes

Format Analysis: Decodes ETag components based on patterns:

Regex pattern matching for Apache hex/decimal

Hash length detection for Nginx

Colon separation for IIS

Information Disclosure Check: Identifies leaked metadata

Security Tests: Performs conditional, compression, and range tests

Content Verification: Downloads and hashes content for comparison

###ETag Format Decoding
Apache (hex)
```
Format: inode_hex-size_hex-mtime_hex
Example: "7a3f-1e4a-5b8c2d1f"
Decoded: inode=31295, size=7754, mtime=1537026725
Apache (decimal)
text
Format: inode-size-mtime
Example: "31295-7754-1537026725"
Nginx
text
Format: hex_hash
Example: "5d41402abc4b2a76b9719d911017c592" (MD5)
Example: "da39a3ee5e6b4b0d3255bfef95601890afd80709" (SHA1)
IIS
text
Format: timestamp_hex:changeNumber_hex
Example: "5f8d9e1a:3b7a"
Decoded: timestamp=1603041820, changeNumber=15226

```
##📝 Requirements
Python 3.6+

requests library

Install Dependencies
bash
pip install requests
🗂️ Project Structure
text
etag-analyzer/
├── Etag_ext.py          # Main script
├── README.md            # This file
├── LICENSE              # MIT License
└── examples/            # Example outputs
    ├── apache_output.txt
    ├── nginx_output.txt
    └── iis_output.txt
##🤝 Contributing
Contributions are welcome! Please feel free to submit a Pull Request.
