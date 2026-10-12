import pathlib, subprocess, pytest
from testserver.server import start
from webscan.checks import check_headers, check_cookies
from webscan.cli import scan, main

ROOT = pathlib.Path(__file__).resolve().parent.parent
CA = str(ROOT / "testserver/certs/ca.pem")

@pytest.fixture(scope="session", autouse=True)
def certs():
    if not (ROOT / "testserver/certs/ca.pem").exists():
        subprocess.run([str(ROOT / "testserver/make_certs.sh")], check=True)

@pytest.fixture(scope="session")
def servers(certs):
    g = start("good")[1]
    return {"good": g, "redirect": start(f"redirect:https://localhost:{g}/")[1], "bad_tls": start("bad_tls")[1],
            "expired": start("expired")[1], "plain": start("plain")[1], "noredirect": start("plain")[1]}

checks = lambda r: {f["check"] for f in r["findings"]}

def test_good_server_grade_a(servers):
    r = scan(f"https://localhost:{servers['good']}/", CA, servers["redirect"])
    assert r["grade"] == "A" and r["findings"] == [] and r["info"]["tls"]["version"] == "TLSv1.3"

def test_bad_tls_detects_legacy_protocols_and_selfsigned(servers):
    r = scan(f"https://localhost:{servers['bad_tls']}/", CA)
    msgs = " ".join(f["message"] for f in r["findings"])
    assert "TLSv1.0" in msgs and "TLSv1.1" in msgs and "self-signed" in msgs and r["grade"] == "F"

def test_expired_cert_is_critical(servers):
    r = scan(f"https://localhost:{servers['expired']}/", CA)
    assert any(f["severity"] == "critical" and "expired" in f["message"] for f in r["findings"]) and r["grade"] == "F"

def test_plain_http(servers):
    assert {"NO_TLS", "CORS", "COOKIE_SECURE", "DISCLOSURE"} <= checks(scan(f"http://localhost:{servers['plain']}/"))

def test_missing_https_redirect(servers):
    r = scan(f"https://localhost:{servers['good']}/", CA, servers["noredirect"])
    assert "HTTPS_REDIRECT" in checks(r)

def test_header_rules_unit():
    assert {"HSTS", "CSP", "CLICKJACK", "NOSNIFF", "REFERRER"} <= {f["check"] for f in check_headers({}, True)}
    assert check_headers({"Strict-Transport-Security": "max-age=60", "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                          "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"}, True)[0]["message"].startswith("HSTS max-age")

def test_cookie_rules_unit():
    assert check_cookies(["sid=1; Secure; HttpOnly; SameSite=Strict"], True) == []
    assert {f["check"] for f in check_cookies(["sid=1"], True)} == {"COOKIE_SECURE", "COOKIE_HTTPONLY", "COOKIE_SAMESITE"}

def test_cli_exit_code(servers):
    assert main([f"https://localhost:{servers['good']}/", "--cafile", CA]) == 0
    assert main([f"http://localhost:{servers['plain']}/"]) == 1
