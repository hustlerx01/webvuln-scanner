"""Local lab targets. python -m testserver.server -> prints ports. Profiles: good (HTTPS), bad_tls (HTTPS), expired (HTTPS), plain (HTTP), redirect (HTTP->good)."""
import http.server, pathlib, ssl, threading, time

CERTS = pathlib.Path(__file__).resolve().parent / "certs"
GOOD_H = {"Strict-Transport-Security": "max-age=31536000; includeSubDomains", "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
          "X-Content-Type-Options": "nosniff", "Referrer-Policy": "strict-origin-when-cross-origin", "X-Frame-Options": "DENY"}
BAD_H = {"Server": "Apache/2.2.15 (CentOS)", "X-Powered-By": "PHP/5.4.16", "Access-Control-Allow-Origin": "*",
         "Access-Control-Allow-Credentials": "true", "Content-Security-Policy": "default-src * 'unsafe-inline'"}
GOOD_C = ["sessionid=abc; Secure; HttpOnly; SameSite=Lax; Path=/"]
BAD_C = ["PHPSESSID=abc; Path=/", "tracking=1; SameSite=None"]

def handler(headers, cookies, redirect_to=None):
    class H(http.server.BaseHTTPRequestHandler):
        server_version = "lab"; sys_version = ""
        def do_GET(self):
            if redirect_to:
                self.send_response(301); self.send_header("Location", redirect_to); self.end_headers(); return
            self.send_response(200)
            for k, v in headers.items(): self.send_header(k, v)
            for c in cookies: self.send_header("Set-Cookie", c)
            self.send_header("Content-Type", "text/html"); self.end_headers(); self.wfile.write(b"<h1>lab</h1>")
        def log_message(self, *a): pass
    return H

def start(profile, port=0):
    if profile == "good": h, ctx = handler(GOOD_H, GOOD_C), ("good", ssl.TLSVersion.TLSv1_2)
    elif profile == "bad_tls": h, ctx = handler(BAD_H, BAD_C), ("bad", ssl.TLSVersion.TLSv1)
    elif profile == "expired": h, ctx = handler(GOOD_H, GOOD_C), ("exp", ssl.TLSVersion.TLSv1_2)
    elif profile == "plain": h, ctx = handler(BAD_H, BAD_C), None
    elif profile.startswith("redirect:"): h, ctx = handler({}, [], redirect_to=profile.split(":", 1)[1]), None
    class Quiet(http.server.ThreadingHTTPServer):
        def handle_error(self, request, client_address): pass  # TLS version probes drop connections on purpose
    srv = Quiet(("127.0.0.1", port), h)
    if ctx:
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); name, minv = ctx
        if minv == ssl.TLSVersion.TLSv1: c.set_ciphers("ALL:@SECLEVEL=0")
        c.minimum_version = minv
        if name == "bad": c.maximum_version = ssl.TLSVersion.TLSv1_2
        c.load_cert_chain(CERTS / f"{name}.pem", CERTS / f"{name}.key")
        srv.socket = c.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]

if __name__ == "__main__":
    g = start("good")[1]
    ports = {"good": g, "bad_tls": start("bad_tls")[1], "expired": start("expired")[1], "plain": start("plain")[1],
             "redirect": start(f"redirect:https://localhost:{g}/")[1]}
    print(ports, flush=True)
    while True: time.sleep(3600)
