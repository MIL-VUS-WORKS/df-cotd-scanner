#!/usr/bin/env python3
"""
Danfoss AK-SM 8xxA — Non-intrusive Code of The Day Vulnerability Scanner


Usage:

    python df-cotd-scanner.py https://127.0.0.1:443 
    python df-cotd-scanner.py --targets hosts.txt 
    python df-cotd-scanner.py 10.0.0.5 --timeout 10 --json

"""

import sys
import re
import ssl
import json
import socket
import argparse
import urllib.request
import urllib.parse
import urllib.error
from urllib.parse import urlparse, urlunparse

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")


FIXED_CODE_OF_DAY = (4, 2)        
RECOMMENDED_FIXED = (4, 3, 1)     
LEGACY_FIXED      = (3, 3)        


XML_VERSION_PROBES = [
    '<cmd action="read_version" version="C" lang="eng"/>',
    '<cmd action="read_sw_version" version="C" lang="eng"/>',
    '<cmd action="read_device_info" version="C" lang="eng"/>',
    '<cmd action="read_general" version="C" lang="eng"/>',
]


XML_FINGERPRINT_PROBE = '<cmd action="read_date_time" version="C" lang="eng"/>'


HTTP_VERSION_PATHS = ["/", "/index.html", "/login", "/version"]# Covering paths


VERSION_PATTERNS = [
    re.compile(r"<\s*(?:sw_)?version\s*>\s*([RVv]?\d+(?:\.\d+){1,2})", re.I),
    re.compile(r"\b(?:version|release|firmware|sw)\b[^0-9RVv]{0,12}"
               r"([RVv]?\d+(?:\.\d+){1,2})", re.I),
    re.compile(r"\b([RV]\d+\.\d+(?:\.\d+)?)\b"),
]


def make_ssl_context():
    """AK-SM devices commonly use self-signed certs; don't fail on that."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    except Exception:
        return ssl._create_unverified_context()


def normalize_base_url(url):
    u = url.strip()
    if not re.match(r"^https?://", u, re.I):
        
        u = "https://" + u
    p = urlparse(u)
    return urlunparse((p.scheme, p.netloc, "", "", "", "")).rstrip("/")


def http_request(url, data=None, timeout=15):
    hdrs = {"User-Agent": UA, "Accept": "*/*", "Connection": "close"}
    if data is not None:
        data = data.encode("utf-8")
        hdrs["Content-Type"] = "text/plain"
    req = urllib.request.Request(url, data=data, headers=hdrs,
                                 method="POST" if data is not None else "GET")
    ctx = make_ssl_context()
    with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", "replace")
        return resp.status, body


def post_xml(base_url, xml_body, timeout=15):
    payload = "xml=" + urllib.parse.quote(xml_body, safe="")
    return http_request(base_url + "/xml.cgi", data=payload, timeout=timeout)


def parse_version(text):
    """Return a normalized (major, minor[, patch]) tuple, or None."""
    for pat in VERSION_PATTERNS:
        m = pat.search(text)
        if m:
            raw = m.group(1).lstrip("RVrv")
            parts = tuple(int(x) for x in raw.split("."))
            if 1 <= len(parts) <= 3 and parts[0] < 100:  
                return parts, m.group(1)
    return None


def cmp_version(v, threshold):
    """Compare version tuples of possibly different length. -1 / 0 / 1."""
    n = max(len(v), len(threshold))
    a = tuple(list(v) + [0] * (n - len(v)))
    b = tuple(list(threshold) + [0] * (n - len(threshold)))
    return (a > b) - (a < b)


def fingerprint(base_url, timeout):
    """Best-effort confirm this is an AK-SM-style device. Read-only."""
    try:
        st, body = post_xml(base_url, XML_FINGERPRINT_PROBE, timeout)
        if "<year>" in body or "date_time" in body.lower():
            return True, "AK-SM XML API responded (date/time endpoint)"
    except Exception:
        pass
    
    try:
        st, body = http_request(base_url + "/", timeout=timeout)
        if re.search(r"AK-SM|System\s*Manager|Danfoss", body, re.I):
            return True, "Management interface banner matched"
    except Exception:
        pass
    return False, "No AK-SM signature observed"


def read_version(base_url, timeout):
    """Try each unauthenticated version probe; return (tuple, raw, source)."""
    for probe in XML_VERSION_PROBES:
        try:
            st, body = post_xml(base_url, probe, timeout)
            pv = parse_version(body)
            if pv:
                return pv[0], pv[1], "xml.cgi " + re.search(r'action="([^"]+)"', probe).group(1)
        except Exception:
            continue
    for path in HTTP_VERSION_PATHS:
        try:
            st, body = http_request(base_url + path, timeout=timeout)
            pv = parse_version(body)
            if pv:
                return pv[0], pv[1], "GET " + path
        except Exception:
            continue
    return None, None, None


def classify(version):
    """Map a version tuple to a verdict + advisory notes."""
    cves = []
    if cmp_version(version, LEGACY_FIXED) < 0:
        cves += ["CVE-2023-25913/14/15 (legacy auth-bypass / RCE)"]
    if cmp_version(version, FIXED_CODE_OF_DAY) < 0:
        cves += ["CVE-2025-41450 (code-of-the-day auth bypass)"]
        return "VULNERABLE", cves
    if cmp_version(version, RECOMMENDED_FIXED) < 0:
        cves += ["CVE-2025-41451 / CVE-2025-41452 (fixed in R4.3.1)"]
        return "NOT_FULLY_PATCHED", cves
    return "UP_TO_DATE", cves


def scan_target(target, timeout):
    base = normalize_base_url(target)
    result = {"target": base, "status": None, "version": None,
              "verdict": None, "cves": [], "detail": ""}

    is_aksm, why = fingerprint(base, timeout)
    if not is_aksm:
        result["status"] = "NOT_AKSM_OR_UNREACHABLE"
        result["detail"] = why
        return result

    ver, raw, source = read_version(base, timeout)
    if ver is None:
        result["status"] = "UNKNOWN"
        result["detail"] = ("Confirmed AK-SM but could not read a version from "
                            "unauthenticated endpoints — verify manually.")
        return result

    verdict, cves = classify(ver)
    result["status"] = "OK"
    result["version"] = raw
    result["verdict"] = verdict
    result["cves"] = cves
    result["detail"] = "version read via %s" % source
    return result


def verdict_line(r):
    if r["status"] == "NOT_AKSM_OR_UNREACHABLE":
        return "[-] %s  not an AK-SM / unreachable (%s)" % (r["target"], r["detail"])
    if r["status"] == "UNKNOWN":
        return "[?] %s  AK-SM confirmed, VERSION UNKNOWN — check manually" % r["target"]
    tag = {
        "VULNERABLE":        "[!] VULNERABLE",
        "NOT_FULLY_PATCHED": "[~] NEEDS UPDATE",
        "UP_TO_DATE":        "[+] up to date",
    }[r["verdict"]]
    line = "%s  %s  version=%s" % (tag, r["target"], r["version"])
    if r["cves"]:
        line += "\n        affected by: " + "; ".join(r["cves"])
    if r["verdict"] in ("VULNERABLE", "NOT_FULLY_PATCHED"):
        line += "\n        remediation: upgrade to firmware R4.3.1 or later"
    return line


def main():
    ap = argparse.ArgumentParser(
        description="Non-intrusive version scanner for Danfoss AK-SM 8xxA products "
                    "(CVE-2025-41450 and related)")
    ap.add_argument("target", nargs="?", help="host or URL (e.g. 10.0.0.5(by default script goes for https) or http://10.0.0.5/)")
    ap.add_argument("--targets", help="file with one host/URL per line")
    ap.add_argument("--timeout", type=float, default=15, help="per-request timeout seconds")
    ap.add_argument("--json", action="store_true", help="emit JSON results")
    args = ap.parse_args()

    targets = []
    if args.target:
        targets.append(args.target)
    if args.targets:
        try:
            with open(args.targets) as fh:
                targets += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        except OSError as e:
            print("ERROR reading --targets file: %s" % e, file=sys.stderr)
            sys.exit(3)
    if not targets:
        ap.print_help()
        sys.exit(3)

    socket.setdefaulttimeout(args.timeout)
    results = []
    for t in targets:
        try:
            results.append(scan_target(t, args.timeout))
        except Exception as e:
            results.append({"target": t, "status": "ERROR", "detail": repr(e),
                            "version": None, "verdict": None, "cves": []})

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print("Danfoss AK-SM 8xxA version scan — %d target(s)\n" % len(results))
        for r in results:
            if r["status"] == "ERROR":
                print("[x] %s  error: %s" % (r["target"], r["detail"]))
            else:
                print(verdict_line(r))
        print()

    any_vuln = any(r.get("verdict") == "VULNERABLE" for r in results)
    any_unknown = any(r.get("status") == "UNKNOWN" for r in results)
    sys.exit(1 if any_vuln else 2 if any_unknown else 0)


if __name__ == "__main__":
    main()
