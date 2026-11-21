"""Fails the GitHub job (so GitHub emails you) when most feeds failed last night."""
import json, os, sys
D = json.load(open(os.path.join(os.path.dirname(__file__), "..", "site", "data", "latest.json"), encoding="utf-8"))
h = D["meta"].get("health", {})
failed, total = len(h.get("failed", [])), h.get("total", 0)
print(f"{failed} of {total} sources failed")
for f in h.get("failed", []):
    print(" -", f["n"], ":", f["err"])
sys.exit(1 if total and failed > total / 2 else 0)
