#!/usr/bin/env python3
"""
HTML quick-scan for suspicious patterns.
 - False positives are possible; treat results as indicators, not proof.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import json

# --- Configuration ---
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; html-scanner/1.0; +https://example.local/)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}
REQUEST_TIMEOUT = 10  # seconds
VERIFY_SSL = True

# Edit these to add domains, regexes, or suspicious resource patterns
blacklisted_domains = {
    "malicious-site.com",
    "bad.example",
}
blacklisted_patterns = [
    re.compile(r"eval\(", re.I),
    re.compile(r"document\.write\(", re.I),
    re.compile(r"window\.location\s*=", re.I),
    re.compile(r"atob\(", re.I),
    re.compile(r"unescape\(", re.I),
    re.compile(r"^data:", re.I),
]
suspicious_input_names = {"password", "pwd", "creditcard", "ccnumber", "ssn"}

# --- Helpers ---
def fetch_html(url: str) -> str:
    """Fetch page HTML robustly, with simple error handling."""
    try:
        resp = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT, verify=VERIFY_SSL)
        resp.raise_for_status()
        # small sanity check
        content_type = resp.headers.get("Content-Type", "")
        if "html" not in content_type.lower():
            raise ValueError(f"Content-Type does not look like HTML: {content_type}")
        return resp.text
    except Exception as e:
        raise RuntimeError(f"Failed to fetch {url!r}: {e}")

def domain_of(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""

def looks_external(resource_url: str, base_url: str) -> bool:
    if not resource_url:
        return False
    joined = urljoin(base_url, resource_url)
    return domain_of(joined).lower() != domain_of(base_url).lower()

def check_blacklist_domain(url: str) -> bool:
    d = domain_of(url).lower()
    return any(d.endswith(b) for b in blacklisted_domains)

# --- Analysis ---
def analyze_html(html: str, base_url: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    findings = {"scripts": [], "forms": [], "inputs": [], "iframes": [], "meta": [], "links": [], "suspicious_text": []}

    # scripts
    for s in soup.find_all("script"):
        src = s.get("src")
        text = (s.string or "")[:500]  # sample of inline JS
        info = {"src": src, "external": bool(src and looks_external(src, base_url)), "blacklisted_domain": bool(src and check_blacklist_domain(src)), "inline_sample": text}
        # scan inline/script text for suspicious patterns
        for pat in blacklisted_patterns:
            if pat.search(text or ""):
                info.setdefault("inline_matches", []).append(pat.pattern)
        findings["scripts"].append(info)

    # forms
    for f in soup.find_all("form"):
        action = f.get("action") or ""
        method = (f.get("method") or "GET").upper()
        full_action = urljoin(base_url, action) if action else base_url
        info = {
            "action": full_action,
            "method": method,
            "external": looks_external(full_action, base_url),
            "blacklisted_domain": check_blacklist_domain(full_action),
            "inputs": []
        }
        for inp in f.find_all("input"):
            in_name = inp.get("name", "")
            in_type = inp.get("type", "text")
            info["inputs"].append({"name": in_name, "type": in_type})
            if in_type.lower() == "hidden" and in_name.lower() in suspicious_input_names:
                info.setdefault("warnings", []).append("Hidden input with suspicious name")
            if in_type.lower() == "password" and in_name.lower() not in suspicious_input_names:
                # normal password field but record it
                info.setdefault("password_fields", 0)
                info["password_fields"] = info.get("password_fields", 0) + 1
        findings["forms"].append(info)

    # inputs that aren't inside forms (possible exfil)
    for inp in soup.find_all("input"):
        in_name = inp.get("name", "")
        in_type = inp.get("type", "text")
        if in_type.lower() == "hidden" and in_name.lower() in suspicious_input_names:
            findings["inputs"].append({"name": in_name, "type": in_type, "note": "hidden suspicious name"})

    # iframes
    for ifr in soup.find_all("iframe"):
        src = ifr.get("src") or ""
        info = {"src": urljoin(base_url, src), "external": looks_external(src, base_url), "blacklisted_domain": check_blacklist_domain(src)}
        findings["iframes"].append(info)

    # meta / CSP
    for meta in soup.find_all("meta"):
        name = meta.get("name", "").lower()
        http_equiv = meta.get("http-equiv", "").lower()
        content = meta.get("content", "")
        if "content-security-policy" in http_equiv or "csp" in name:
            findings["meta"].append({"name": name, "http_equiv": http_equiv, "content": content})

    # links (anchor tags)
    for a in soup.find_all("a", href=True):
        href = a["href"]
        full = urljoin(base_url, href)
        findings["links"].append({"href": full, "external": looks_external(full, base_url), "blacklisted_domain": check_blacklist_domain(full)})

    # search page text for suspicious patterns (simple heuristics)
    text_blob = soup.get_text(separator="\n")[:4000]
    for pat in blacklisted_patterns:
        if pat.search(text_blob):
            findings["suspicious_text"].append(pat.pattern)

    return findings

# --- Runner / example usage ---
def scan_url(url: str) -> dict:
    report = {"url": url, "error": None, "summary": {}, "details": None}
    try:
        html = fetch_html(url)
    except Exception as e:
        report["error"] = str(e)
        return report

    details = analyze_html(html, url)
    # simple summary counts & flags
    summary = {
        "scripts_total": len(details["scripts"]),
        "forms_total": len(details["forms"]),
        "iframes_total": len(details["iframes"]),
        "links_total": len(details["links"]),
        "suspicious_inline_matches": sum(1 for s in details["scripts"] if s.get("inline_matches")),
        "external_forms": sum(1 for f in details["forms"] if f.get("external")),
        "forms_with_blacklisted_domain": sum(1 for f in details["forms"] if f.get("blacklisted_domain")),
        "scripts_with_blacklisted_domain": sum(1 for s in details["scripts"] if s.get("blacklisted_domain")),
        "iframes_blacklisted": sum(1 for i in details["iframes"] if i.get("blacklisted_domain")),
        "suspicious_text_matches": len(details["suspicious_text"]),
    }
    report["summary"] = summary
    report["details"] = details
    return report

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Quick HTML scanner for suspicious resources")
    parser.add_argument("url", help="URL to scan (include scheme, e.g. https://example.com)")
    parser.add_argument("--json", action="store_true", help="print JSON output")
    args = parser.parse_args()

    result = scan_url(args.url)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        # human-readable
        print("Scan report for:", result["url"])
        if result["error"]:
            print("ERROR:", result["error"])
        else:
            for k, v in result["summary"].items():
                print(f"  {k}: {v}")
            # print a few notable findings
            scripts_with_inline = [s for s in result["details"]["scripts"] if s.get("inline_matches") or s.get("blacklisted_domain")]
            if scripts_with_inline:
                print("\nSuspicious scripts (first 5):")
                for s in scripts_with_inline[:5]:
                    print(" -", s)
            forms_with_warnings = [f for f in result["details"]["forms"] if f.get("warnings") or f.get("blacklisted_domain") or f.get("external")]
            if forms_with_warnings:
                print("\nSuspicious forms (first 5):")
                for f in forms_with_warnings[:5]:
                    print(" -", f)


