"""python -m webscan.cli URL [--json] [--cafile ca.pem] [--fail-on high]"""
import argparse, http.client, json, ssl, sys
from urllib.parse import urlsplit
from .checks import check_headers, check_cookies, check_tls, F

SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
PENALTY = {"info": 0, "low": 3, "medium": 8, "high": 15, "critical": 30}

def fetch(url, cafile=None):
    p = urlsplit(url); https = p.scheme == "https"
    if https:
        ctx = ssl.create_default_context(cafile=cafile); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE  # TLS judged separately
        conn = http.client.HTTPSConnection(p.hostname, p.port or 443, timeout=10, context=ctx)
    else:
        conn = http.client.HTTPConnection(p.hostname, p.port or 80, timeout=10)
    conn.request("GET", p.path or "/", headers={"User-Agent": "webscan/0.1"})
    r = conn.getresponse(); r.read()
    return r.status, dict(r.getheaders()), r.headers.get_all("Set-Cookie") or []

def scan(url, cafile=None, http_redirect_port=None):
    p = urlsplit(url); https = p.scheme == "https"; findings, info = [], {"url": url}
    status, headers, cookies = fetch(url, cafile); info["status"] = status
    findings += check_headers(headers, https) + check_cookies(cookies, https)
    if https:
        f, ti = check_tls(p.hostname, p.port or 443, cafile); findings += f; info["tls"] = ti
        if http_redirect_port:
            try:
                s, h, _ = fetch(f"http://{p.hostname}:{http_redirect_port}/")
                if not (300 <= s < 400 and h.get("Location", h.get("location", "")).startswith("https://")):
                    findings.append(F("HTTPS_REDIRECT", "medium", f"HTTP port {http_redirect_port} does not redirect to HTTPS (status {s})"))
            except OSError:
                pass
    else:
        findings.append(F("NO_TLS", "high", "site served over plain HTTP"))
    score = max(0, 100 - sum(PENALTY[f["severity"]] for f in findings))
    if any(f["severity"] == "critical" for f in findings): score = min(score, 39)  # critical caps at F
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    return {"info": info, "score": score, "grade": grade, "findings": findings}

def main(argv=None):
    ap = argparse.ArgumentParser(); ap.add_argument("url"); ap.add_argument("--json", action="store_true")
    ap.add_argument("--cafile"); ap.add_argument("--http-port", type=int); ap.add_argument("--fail-on", default="high", choices=list(SEV))
    a = ap.parse_args(argv); r = scan(a.url, a.cafile, a.http_port)
    if a.json: print(json.dumps(r, indent=2))
    else:
        print(f"{a.url}  grade {r['grade']} ({r['score']}/100)  {r['info'].get('tls', '')}")
        for f in sorted(r["findings"], key=lambda f: -SEV[f["severity"]]):
            print(f"  [{f['severity'].upper():8}] {f['check']:15} {f['message']}" + (f"  ({f['evidence']})" if f['evidence'] else ""))
    return 1 if any(SEV[f["severity"]] >= SEV[a.fail_on] for f in r["findings"]) else 0

if __name__ == "__main__":
    sys.exit(main())
