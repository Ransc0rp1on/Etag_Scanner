#!/usr/bin/env python3

import requests
import sys
import hashlib
import argparse
import re
import time
from datetime import datetime

# ------------------------------------------------------------
#  ETag parser
# ------------------------------------------------------------
def parse_etag(etag_str):
    """Split ETag into weak flag and raw value (stripped of quotes)."""
    etag_str = etag_str.strip()
    weak = False
    if etag_str.startswith('W/"'):
        weak = True
        raw = etag_str[3:-1]   # remove W/" and trailing "
    elif etag_str.startswith('"') and etag_str.endswith('"'):
        raw = etag_str[1:-1]
    else:
        raw = etag_str
    return weak, raw

def decode_apache_mtime(mtime_hex):
    """
    Decode Apache mtime from hex.
    - 8 hex chars → 32-bit seconds (Apache 1.x)
    - longer → 64-bit microseconds (Apache 2.x) → divide by 1,000,000
    Returns (timestamp_seconds, datetime_str) or (None, None) if invalid.
    """
    if not mtime_hex:
        return None, None
    mtime_hex = mtime_hex.lower()
    try:
        if len(mtime_hex) == 8:
            # 32-bit seconds
            ts = int(mtime_hex, 16)
            return ts, datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S UTC')
        else:
            # 64-bit microseconds – extract high and low 32 bits
            # Low bits = last 8 hex chars, high bits = everything before
            low_hex = mtime_hex[-8:] if len(mtime_hex) >= 8 else mtime_hex
            high_hex = mtime_hex[:-8] if len(mtime_hex) > 8 else ''
            # Pad high bits to 8 chars (Nessus logic)
            if high_hex and len(high_hex) < 8:
                high_hex = high_hex.zfill(8)
            high = int(high_hex, 16) if high_hex else 0
            low = int(low_hex, 16)
            mtime_micro = (high << 32) | low
            ts = mtime_micro // 1_000_000   # convert to seconds
            return ts, datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S UTC')
    except:
        return None, None

def analyze_etag_format(raw_etag):
    """
    Attempt to decode components from the raw ETag string.
    Returns dict with format, components, readable values, and disclosure flags.
    """
    result = {
        "format": "unknown",
        "components": {},
        "readable": {},
        "disclosure": {"inode": False, "size": False, "mtime": False}
    }

    # ----- Apache default (inode-size-mtime) in hex or decimal -----
    hex_pattern = r'^([a-f0-9]+)-([a-f0-9]+)-([a-f0-9]+)$'
    dec_pattern = r'^(\d+)-(\d+)-(\d+)$'

    m = re.match(hex_pattern, raw_etag, re.I)
    if m:
        inode_hex, size_hex, mtime_hex = m.groups()
        inode = int(inode_hex, 16)
        size = int(size_hex, 16)
        mtime_ts, mtime_str = decode_apache_mtime(mtime_hex)

        result["format"] = "Apache (hex)"
        result["components"] = {"inode": inode, "size": size, "mtime_hex": mtime_hex}
        result["readable"]["size"] = f"{size} bytes ({size/1024:.2f} KB)"
        if mtime_ts:
            result["readable"]["mtime"] = mtime_str
        result["readable"]["inode"] = inode
        result["disclosure"] = {"inode": True, "size": True, "mtime": bool(mtime_ts)}
        return result

    m = re.match(dec_pattern, raw_etag)
    if m:
        inode, size, mtime = map(int, m.groups())
        result["format"] = "Apache (decimal)"
        result["components"] = {"inode": inode, "size": size, "mtime": mtime}
        result["readable"]["size"] = f"{size} bytes ({size/1024:.2f} KB)"
        result["readable"]["mtime"] = datetime.utcfromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S UTC')
        result["readable"]["inode"] = inode
        result["disclosure"] = {"inode": True, "size": True, "mtime": True}
        return result

    # ----- Nginx default (hex hash) -----
    hex_only = r'^[a-f0-9]+$'
    if re.match(hex_only, raw_etag, re.I) and len(raw_etag) in (8,16,32,40,64):
        result["format"] = "Nginx-style hex hash"
        result["components"] = {"hash": raw_etag}
        result["readable"]["hash"] = raw_etag
        if len(raw_etag) == 32:
            result["readable"]["hint"] = "Possible MD5"
        elif len(raw_etag) == 40:
            result["readable"]["hint"] = "Possible SHA1"
        elif len(raw_etag) == 64:
            result["readable"]["hint"] = "Possible SHA256"
        return result

    # ----- IIS / ASP.NET (timestamp:changeNumber) -----
    iis_pattern = r'^([a-f0-9]+):([a-f0-9]+)$'
    m = re.match(iis_pattern, raw_etag, re.I)
    if m:
        ts_hex, change_hex = m.groups()
        timestamp = int(ts_hex, 16) if ts_hex else 0
        change_number = int(change_hex, 16) if change_hex else 0
        result["format"] = "IIS/ASP.NET"
        result["components"] = {"timestamp_hex": ts_hex, "changeNumber_hex": change_hex}
        result["readable"]["changeNumber"] = change_number
        if timestamp:
            dt = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')
            result["readable"]["timestamp"] = dt
        result["disclosure"] = {"timestamp": bool(timestamp)}
        return result

    return result

def report_information_disclosure(fmt_info, server_header):
    """Print a Nessus-style security warning if inode or other sensitive data is leaked."""
    if fmt_info["disclosure"].get("inode"):
        print("\n[!] SECURITY WARNING: INFORMATION DISCLOSURE DETECTED [!]")
        print("    The server is leaking internal filesystem metadata via the ETag header.")
        print("    This is similar to the classic Apache ETag inode disclosure vulnerability.")
        print("\n    Disclosed Information:")
        if "inode" in fmt_info["readable"]:
            print(f"      - Inode number  : {fmt_info['readable']['inode']}")
        if "size" in fmt_info["readable"]:
            print(f"      - File size     : {fmt_info['readable']['size']}")
        if "mtime" in fmt_info["readable"]:
            print(f"      - Modified time : {fmt_info['readable']['mtime']}")
        print("\n    Potential Impact: Inode numbers can aid in fingerprinting the filesystem")
        print("    and may be used in targeted attacks. File sizes and modification times")
        print("    reveal non-public information about the resource.")
        if "Apache" in server_header:
            print("    Server identifies as Apache – this is a known configuration weakness.")
        else:
            print("    Although the server does not identify as Apache, the ETag format")
            print("    matches Apache's default. This may be a misconfiguration or a different")
            print("    server emulating Apache ETags.")
    elif fmt_info["disclosure"].get("timestamp"):
        print("\n[*] Information Disclosure (Low Severity):")
        print("    The ETag contains a timestamp (IIS/ASP.NET style).")
        print(f"      - Timestamp : {fmt_info['readable']['timestamp']}")
        print("    This reveals the approximate generation time of the response.")

# ------------------------------------------------------------
#  Test suites (fully implemented)
# ------------------------------------------------------------
def test_conditional_requests(url, etag_strong, etag_weak):
    """Perform If-None-Match and If-Match tests."""
    print("\n[ CONDITIONAL REQUEST TESTS ]")
    
    # If-None-Match test (for cache validation)
    headers = {"If-None-Match": f'"{etag_strong}"'}
    try:
        r = requests.get(url, headers=headers, allow_redirects=True, timeout=10)
        if r.status_code == 304:
            print("[+] If-None-Match with strong ETag: 304 Not Modified (expected)")
        else:
            print(f"[?] If-None-Match with strong ETag: {r.status_code} (unexpected)")
    except Exception as e:
        print(f"[-] If-None-Match test failed: {e}")
    
    # If-Match test (for optimistic concurrency)
    headers = {"If-Match": f'"{etag_strong}"'}
    try:
        r = requests.get(url, headers=headers, allow_redirects=True, timeout=10)
        if r.status_code == 200:
            print("[+] If-Match with strong ETag: 200 OK (expected)")
        else:
            print(f"[?] If-Match with strong ETag: {r.status_code} (unexpected)")
    except Exception as e:
        print(f"[-] If-Match test failed: {e}")

def test_compression_effect(url, original_etag_weak, original_raw):
    """Test ETag with Accept-Encoding: gzip."""
    print("\n[ COMPRESSION TEST ]")
    headers = {"Accept-Encoding": "gzip"}
    try:
        r = requests.get(url, headers=headers, allow_redirects=True, timeout=10)
        new_etag = r.headers.get("ETag")
        content_encoding = r.headers.get("Content-Encoding", "none")
        print(f"[+] Content-Encoding: {content_encoding}")
        
        if new_etag:
            weak_new, raw_new = parse_etag(new_etag)
            print(f"[+] ETag with gzip: {new_etag}")
            if raw_new == original_raw:
                print("[+] ETag unchanged with compression")
            else:
                print(f"[!] ETag changed with compression: {raw_new} vs {original_raw}")
        else:
            print("[-] No ETag returned with compression")
    except Exception as e:
        print(f"[-] Compression test failed: {e}")

def test_range_request(url, etag_strong):
    """Test ETag with Range request."""
    print("\n[ RANGE REQUEST TEST ]")
    headers = {
        "Range": "bytes=0-99",
        "If-Range": f'"{etag_strong}"'
    }
    try:
        r = requests.get(url, headers=headers, allow_redirects=True, timeout=10)
        if r.status_code == 206:
            content_length = r.headers.get("Content-Length", "unknown")
            print(f"[+] Range request successful (206 Partial Content)")
            print(f"[+] Received {content_length} bytes")
            
            # Verify content matches ETag (first 100 bytes)
            if len(r.content) > 0:
                content_hash = hashlib.md5(r.content).hexdigest()
                print(f"[+] First 100 bytes MD5: {content_hash}")
        elif r.status_code == 200:
            print("[?] Server ignored Range request (returned full content)")
        else:
            print(f"[?] Range request returned {r.status_code}")
    except Exception as e:
        print(f"[-] Range request failed: {e}")

def hash_content(url, etag_raw):
    """Download and hash content for comparison with ETag."""
    print("\n[ CONTENT HASH COMPARISON ]")
    try:
        r = requests.get(url, allow_redirects=True, timeout=10)
        content = r.content
        
        # Calculate various hashes
        md5_hash = hashlib.md5(content).hexdigest()
        sha1_hash = hashlib.sha1(content).hexdigest()
        sha256_hash = hashlib.sha256(content).hexdigest()
        
        print(f"[+] Content length: {len(content)} bytes")
        print(f"[+] MD5: {md5_hash}")
        print(f"[+] SHA1: {sha1_hash[:20]}... (truncated)")
        print(f"[+] SHA256: {sha256_hash[:20]}... (truncated)")
        
        # Compare with ETag
        if etag_raw.lower() == md5_hash:
            print("[+] ETag matches MD5 of content")
        elif etag_raw.lower() == sha1_hash:
            print("[+] ETag matches SHA1 of content")
        elif etag_raw.lower() == sha256_hash:
            print("[+] ETag matches SHA256 of content")
        elif len(etag_raw) == 32 and etag_raw.isalnum():
            print("[?] ETag looks like an MD5 but doesn't match content")
        elif len(etag_raw) == 40 and etag_raw.isalnum():
            print("[?] ETag looks like a SHA1 but doesn't match content")
        else:
            print("[?] ETag does not match any common hash of content")
            
    except Exception as e:
        print(f"[-] Content download failed: {e}")

# ------------------------------------------------------------
#  Main analysis routine
# ------------------------------------------------------------
def analyze_etag(url, args):
    print(f"\n=== ETag Analysis for {url} ===\n")

    # ---- Initial HEAD request ----
    try:
        r_head = requests.head(url, allow_redirects=True, timeout=10)
    except Exception as e:
        print(f"[-] HEAD request failed: {e}")
        return

    etag_header = r_head.headers.get("ETag")
    server_header = r_head.headers.get("Server", "unknown")
    print(f"[+] Server: {server_header}")
    if not etag_header:
        print("[-] No ETag header found. Exiting.")
        return

    print(f"[+] Raw ETag: {etag_header}")
    weak, raw_value = parse_etag(etag_header)
    print(f"[+] Weak: {weak}")
    print(f"[+] Stripped value: {raw_value}")

    # ---- ETag format analysis ----
    print("\n[ ETAG FORMAT ANALYSIS ]")
    fmt_info = analyze_etag_format(raw_value)
    print(f"[*] Detected format: {fmt_info['format']}")
    if fmt_info['components']:
        print("[*] Decoded components:")
        for k, v in fmt_info['components'].items():
            print(f"    - {k}: {v}")
    if fmt_info['readable']:
        print("[*] Human readable:")
        for k, v in fmt_info['readable'].items():
            print(f"    - {k}: {v}")

    # ---- INFORMATION DISCLOSURE CHECK (Nessus-style) ----
    report_information_disclosure(fmt_info, server_header)

    # ---- Server fingerprint hint ----
    server_hint = ""
    if "Apache" in server_header and fmt_info['format'].startswith("Apache"):
        server_hint = "Matches Apache default ETag format."
    elif "nginx" in server_header and fmt_info['format'] == "Nginx-style hex hash":
        server_hint = "Matches nginx default ETag format."
    elif "IIS" in server_header or "Microsoft-IIS" in server_header:
        if fmt_info['format'] == "IIS/ASP.NET":
            server_hint = "Matches IIS ETag format."
        else:
            server_hint = "Server declares IIS but ETag format is different."
    if server_hint:
        print(f"[*] Fingerprint: {server_hint}")

    # ---- Conditional tests (if enabled) ----
    if args.conditional:
        test_conditional_requests(url, raw_value, raw_value if not weak else raw_value)

    # ---- Compression test (if enabled) ----
    if args.compression:
        test_compression_effect(url, weak, raw_value)

    # ---- Range test (if enabled) ----
    if args.range:
        test_range_request(url, raw_value)

    # ---- Content hash (unless disabled) ----
    if not args.no_hash:
        hash_content(url, raw_value)

    print("\n=== Analysis Complete ===\n")

# ------------------------------------------------------------
#  Entry point
# ------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced ETag header analyzer with Apache disclosure detection")
    parser.add_argument("url", help="Target URL (e.g., https://example.com/file.js)")
    parser.add_argument("--conditional", action="store_true", help="Run conditional request tests")
    parser.add_argument("--compression", action="store_true", help="Test ETag with Accept-Encoding: gzip")
    parser.add_argument("--range", action="store_true", help="Test ETag with Range request")
    parser.add_argument("--no-hash", action="store_true", help="Skip content download & hash comparison")
    parser.add_argument("--full", action="store_true", help="Run all tests (conditional, compression, range)")
    parser.add_argument("--delay", type=float, default=0.5, help="Seconds between requests (default: 0.5)")
    args = parser.parse_args()

    if args.full:
        args.conditional = True
        args.compression = True
        args.range = True

    time.sleep(args.delay)
    analyze_etag(args.url, args)
