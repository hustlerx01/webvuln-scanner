"""Start all lab targets in-process and scan each; writes results/lab_scan.json + .txt"""
import json, pathlib, sys
from testserver.server import start
from webscan.cli import scan, main

CA = str(pathlib.Path("testserver/certs/ca.pem"))
g = start("good")[1]; r = start(f"redirect:https://localhost:{g}/")[1]
targets = {"good": (f"https://localhost:{g}/", r), "bad_tls": (f"https://localhost:{start('bad_tls')[1]}/", None),
           "expired": (f"https://localhost:{start('expired')[1]}/", None), "plain": (f"http://localhost:{start('plain')[1]}/", None)}
res = {}
for name, (url, rp) in targets.items():
    res[name] = scan(url, CA, rp)
    print(f"\n### {name}"); main([url, "--cafile", CA] + (["--http-port", str(rp)] if rp else []))
pathlib.Path("results").mkdir(exist_ok=True)
pathlib.Path("results/lab_scan.json").write_text(json.dumps(res, indent=2))
