"""Builds sample responses in tests/fixtures so the collector can be tested offline.

    python tests/make_fixtures.py
    CIR_FIXTURES=tests/fixtures python collector/run.py
"""
import json
import os
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

HERE = os.path.dirname(os.path.abspath(__file__))
FX = os.path.join(HERE, "fixtures")
ROOT = os.path.dirname(HERE)
os.makedirs(FX, exist_ok=True)
now = datetime.now(timezone.utc)
today = now.date().isoformat()
h = lambda hours: format_datetime(now - timedelta(hours=hours))


def w(name, obj):
    with open(os.path.join(FX, name), "w", encoding="utf-8") as f:
        f.write(obj if isinstance(obj, str) else json.dumps(obj))


def rss(items):
    body = "".join(f"<item><title>{t}</title><link>{l}</link><pubDate>{d}</pubDate><description><![CDATA[<p>{s}</p>]]></description></item>"
                   for t, l, d, s in items)
    return f'<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel><title>t</title>{body}</channel></rss>'


# CISA KEV: everything already in the record, the CVEs the preview left out, and one new flaw today
seed = json.load(open(os.path.join(ROOT, "site", "data", "latest.json"), encoding="utf-8"))
vulns = []
for k in seed["kev"]:
    cve = k["cve"].split(" ")[0]
    vulns.append({"cveID": cve, "vendorProject": k["v"], "product": k["p"], "vulnerabilityName": f"{k['v']} {k['p']} {k['n']} Vulnerability",
                  "dateAdded": k["a"], "dueDate": k["d"] or k["a"], "shortDescription": f"{k['n']} in {k['p']}.",
                  "requiredAction": "Apply mitigations per vendor instructions.", "knownRansomwareCampaignUse": "Unknown"})
for c in ("CVE-2026-96653", "CVE-2026-96654", "CVE-2026-96655"):
    vulns.append({"cveID": c, "vendorProject": "Plex", "product": "Media Server", "vulnerabilityName": "Plex Media Server Chain Vulnerability",
                  "dateAdded": "2026-10-20", "dueDate": "2026-11-10", "shortDescription": "Part of the Plex2Shell chain.", "requiredAction": "Update.", "knownRansomwareCampaignUse": "Unknown"})
vulns.append({"cveID": "CVE-2026-118527", "vendorProject": "Ivanti", "product": "Connect Secure", "vulnerabilityName": "Ivanti Connect Secure Command Injection Vulnerability",
              "dateAdded": "2026-10-30", "dueDate": "2026-11-02", "shortDescription": "Command injection in the chain.", "requiredAction": "Upgrade.", "knownRansomwareCampaignUse": "Unknown"})
vulns.append({"cveID": "CVE-2026-130001", "vendorProject": "Fortinet", "product": "FortiWeb", "vulnerabilityName": "Fortinet FortiWeb Path Traversal Vulnerability",
              "dateAdded": today, "dueDate": (now + timedelta(days=21)).date().isoformat(),
              "shortDescription": "A path traversal flaw in FortiWeb lets an unauthenticated attacker run administrative commands.",
              "requiredAction": "Upgrade to the fixed FortiWeb release or disconnect the management interface.", "knownRansomwareCampaignUse": "Known"})
w("kev.json", {"vulnerabilities": vulns})

w("euvd.json", [{"id": "EUVD-2026-140001", "aliases": "CVE-2026-130555", "description": "Zimbra Collaboration stored XSS exploited against European ministries.",
                 "baseScore": 8.1, "exploitedSince": now.strftime("%b %d, %Y, 12:00:00 AM"),
                 "enisaIdVendor": [{"vendor": {"name": "Synacor"}}], "enisaIdProduct": [{"product": {"name": "Zimbra Collaboration"}}]}])
w("epss0.json", {"data": [{"cve": "CVE-2026-130001", "epss": "0.71", "percentile": "0.99"}, {"cve": "CVE-2026-124194", "epss": "0.12", "percentile": "0.95"},
                          {"cve": "CVE-2026-115731", "epss": "0.43", "percentile": "0.98"}]})
w("nvd-CVE-2026-130001.json", {"vulnerabilities": [{"cve": {"metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.8}}]}}}]})

feeds = {
    "record": [("Hackers steal $25 million from Nordbank through payment vendor", "https://example.org/record/nordbank", h(5),
                "Danish lender Nordbank says attackers used a compromised payments vendor to wire $25 million out of its treasury accounts. The bank confirms the theft and says customer accounts were not touched."),
               ("How to choose an EDR: a buyer's guide", "https://example.org/record/edr", h(3), "Sponsored guide to choosing tools.")],
    "bleeping": [("Nordbank confirms $25 million heist via compromised vendor", "https://example.org/bc/nordbank", h(4),
                  "Nordbank confirmed hackers stole $25 million after breaching a third-party payments provider."),
                 ("Apache Roller CVE-2026-129448 exploited to deploy web shells", "https://example.org/bc/roller", h(8),
                  "Attackers are exploiting CVE-2026-129448 in Apache Roller to drop web shells on blog servers.")],
    "thn": [("Critical Acme Gateway flaw CVE-2026-130777 allows remote code execution, patch released", "https://example.org/thn/acme", h(6),
             "Acme released a patch for a critical remote code execution flaw in Acme Gateway. No exploitation reported yet.")],
    "secweek": [("Acme patches critical Gateway RCE CVE-2026-130777", "https://example.org/sw/acme", h(7), "Acme fixed CVE-2026-130777, a critical RCE.")],
    "darkreading": [("Equinor says cyberattack on IT systems is contained", "https://example.org/dr/equinor", h(2),
                     "Norway's Equinor says the cyberattack on its IT systems has been contained and production was never affected.")],
    "cisa": [("CISA Releases Advisory on Acme Gateway", "https://example.org/cisa/acme", h(9), "CISA urges patching.")],
    "ncsc": [("NCSC warns of phishing campaign against UK councils", "https://example.org/ncsc/councils", h(10), "Advisory.")],
}
w("ransomware.json", [
    {"victim": "Harbor Credit Union", "group_name": "akira", "activity": "Financial Services", "country": "US", "discovered": now.strftime("%Y-%m-%d %H:%M:%S")},
    {"victim": "Some Dental Clinic", "group_name": "qilin", "activity": "Healthcare", "country": "US", "discovered": now.strftime("%Y-%m-%d %H:%M:%S")},
    {"victim": "Widget Manufacturing", "group_name": "akira", "activity": "Manufacturing", "country": "DE", "discovered": now.strftime("%Y-%m-%d %H:%M:%S")}])
w("sec.json", {"hits": {"hits": [{"_id": "0001234567-26-000123:ex99.htm", "_source": {"display_names": ["Midwest Mutual Holdings Inc  (CIK 0001234567)"],
                                                                                         "ciks": ["0001234567"], "file_date": today}}]}})
w("hibp.json", [{"Name": "ShopFast", "Title": "ShopFast", "AddedDate": (now - timedelta(hours=3)).isoformat().replace("+00:00", "Z"), "PwnCount": 2400000,
                 "Description": "In October 2026, online retailer ShopFast suffered a breach exposing 2.4 million customer records.", "DataClasses": ["Email addresses", "Names", "Phone numbers"]}])

cfg = json.load(open(os.path.join(ROOT, "collector", "sources.json"), encoding="utf-8"))
for s in cfg["sources"]:
    if s.get("kind") != "rss":
        continue
    for i, _ in enumerate(s.get("feeds") or [s["url"]]):
        key = s["id"] + (f"-{i}" if i else "")
        w(key + ".xml", rss(feeds.get(key, [])))
print("fixtures written to", FX)
