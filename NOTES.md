# Interview talking points: webvuln-scanner

1. **What it covers.** The classic VAPT config findings: HSTS, CSP, clickjacking, nosniff, Referrer-Policy, CORS `*` with credentials, version disclosure, cookie flags, TLS 1.0/1.1, expired or self-signed certs, HTTP→HTTPS redirect.
2. **Tested against ground truth.** I built 4 lab servers with known misconfigurations (plus a redirect server) so every check has a positive and a negative test. The good server must score A with zero findings, which guards against false positives.
3. **How the TLS probe works.** I pin `minimum_version = maximum_version = TLSv1` on the client with `@SECLEVEL=0` and see whether the handshake completes. I learned the client's own OpenSSL policy limits what you can detect, and documented that.
4. **The bug I hit.** Python 3.13 turns on `VERIFY_X509_STRICT`, so my first lab CA (no keyUsage) was rejected and the *good* server showed "verification failed". I fixed the cert extensions (CA keyUsage, leaf AKI/EKU). Real-world lesson: strict validation catches sloppy internal PKI.
5. **Severity thinking.** A session cookie without `Secure` is high, a tracking cookie is medium. `SameSite=None` without `Secure` is high because browsers reject it. An expired cert is critical and caps the grade at F.
6. **CI-friendly.** `--fail-on` gives an exit code, so it can block a deploy. JSON output can feed a SIEM or dashboard.
7. **Ethics.** Lab-only by default, with a README warning. Only scan what you're authorised to test.
8. **Next steps.** Cipher enumeration, chain/OCSP checks, multi-path crawling, comparison against testssl.sh on a set of public sites (with permission).
