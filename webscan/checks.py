"""Header, cookie and TLS checks. Stdlib only. Each check returns Finding dicts."""
import datetime as dt, re, socket, ssl
from http.cookies import SimpleCookie

def F(check, severity, msg, evidence=""):
    return {"check": check, "severity": severity, "message": msg, "evidence": evidence[:200]}

def check_headers(h: dict, https: bool):
    h = {k.lower(): v for k, v in h.items()}; out = []
    if https:
        hsts = h.get("strict-transport-security")
        if not hsts: out.append(F("HSTS", "high", "Strict-Transport-Security missing"))
        else:
            m = re.search(r"max-age=(\d+)", hsts)
            if not m or int(m.group(1)) < 15552000: out.append(F("HSTS", "medium", "HSTS max-age < 180 days", hsts))
    csp = h.get("content-security-policy")
    if not csp: out.append(F("CSP", "medium", "Content-Security-Policy missing"))
    else:
        if "'unsafe-inline'" in csp and "script-src" in csp or re.search(r"default-src[^;]*'unsafe-inline'", csp):
            out.append(F("CSP", "medium", "CSP allows 'unsafe-inline' scripts", csp))
        if re.search(r"(script-src|default-src)[^;]*\s\*(\s|;|$)", csp): out.append(F("CSP", "medium", "CSP wildcard source", csp))
    if "x-frame-options" not in h and "frame-ancestors" not in (csp or ""):
        out.append(F("CLICKJACK", "medium", "No X-Frame-Options or CSP frame-ancestors"))
    if h.get("x-content-type-options", "").lower() != "nosniff": out.append(F("NOSNIFF", "low", "X-Content-Type-Options: nosniff missing"))
    if "referrer-policy" not in h: out.append(F("REFERRER", "low", "Referrer-Policy missing"))
    for k in ("server", "x-powered-by", "x-aspnet-version"):
        if k in h and re.search(r"\d", h[k]): out.append(F("DISCLOSURE", "low", f"{k} header discloses version", h[k]))
    if h.get("access-control-allow-origin") == "*" and h.get("access-control-allow-credentials", "").lower() == "true":
        out.append(F("CORS", "high", "ACAO * with credentials"))
    elif h.get("access-control-allow-origin") == "*":
        out.append(F("CORS", "info", "ACAO * (fine for public data only)"))
    return out

def check_cookies(set_cookie_headers: list, https: bool):
    out = []
    for raw in set_cookie_headers:
        name = raw.split("=", 1)[0].strip(); low = raw.lower()
        attrs = [a.strip().split("=")[0] for a in low.split(";")[1:]]
        sensitive = re.search(r"sess|auth|token|sid|jwt", name, re.I) is not None
        if "secure" not in attrs: out.append(F("COOKIE_SECURE", "high" if sensitive else "medium", f"cookie '{name}' lacks Secure", raw))
        if "httponly" not in attrs and sensitive: out.append(F("COOKIE_HTTPONLY", "high", f"session cookie '{name}' lacks HttpOnly", raw))
        ss = re.search(r"samesite=(\w+)", low)
        if not ss: out.append(F("COOKIE_SAMESITE", "low", f"cookie '{name}' has no SameSite", raw))
        elif ss.group(1) == "none" and "secure" not in attrs: out.append(F("COOKIE_SAMESITE", "high", f"cookie '{name}' SameSite=None without Secure", raw))
    return out

def _try_version(host, port, ver):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    try: ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError: pass
    ctx.minimum_version = ver; ctx.maximum_version = ver
    try:
        with socket.create_connection((host, port), timeout=5) as s, ctx.wrap_socket(s, server_hostname=host):
            return True
    except (ssl.SSLError, OSError, ValueError):
        return False

def check_tls(host, port=443, cafile=None, now=None):
    out, info = [], {}
    ctx = ssl.create_default_context(cafile=cafile)
    try:
        with socket.create_connection((host, port), timeout=5) as s, ctx.wrap_socket(s, server_hostname=host) as t:
            cert = t.getpeercert(); info.update(version=t.version(), cipher=t.cipher()[0])
            exp = dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
            days = (exp - (now or dt.datetime.now(dt.timezone.utc))).days; info["cert_days_left"] = days
            if days < 0: out.append(F("TLS_CERT", "critical", "certificate expired", cert["notAfter"]))
            elif days < 21: out.append(F("TLS_CERT", "medium", f"certificate expires in {days} days"))
    except ssl.SSLCertVerificationError as e:
        msg = e.verify_message or str(e)
        if "expired" in msg: out.append(F("TLS_CERT", "critical", "certificate expired", msg))
        elif "self-signed" in msg or "self signed" in msg: out.append(F("TLS_CERT", "high", "self-signed / untrusted certificate", msg))
        else: out.append(F("TLS_CERT", "high", "certificate verification failed", msg))
    except (ssl.SSLError, OSError) as e:
        out.append(F("TLS", "high", "TLS handshake failed", str(e))); return out, info
    for ver, name in ((ssl.TLSVersion.TLSv1, "TLSv1.0"), (ssl.TLSVersion.TLSv1_1, "TLSv1.1")):
        if _try_version(host, port, ver): out.append(F("TLS_PROTO", "high", f"server accepts deprecated {name}"))
    info["tls1_3"] = _try_version(host, port, ssl.TLSVersion.TLSv1_3)
    if not info["tls1_3"]: out.append(F("TLS_PROTO", "info", "TLS 1.3 not supported"))
    return out, info
