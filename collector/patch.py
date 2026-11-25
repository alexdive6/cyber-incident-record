"""Our patching: the vendor fixes that apply to the platforms we run.

The inventory (platform names, exact products and versions) is private. It is read from
the PATCH_INVENTORY environment variable (a GitHub repository secret holding JSON) or,
on a local machine, from collector/inventory.local.json, which git ignores.
collector/inventory.example.json shows the format.

Only the platform display name ("Linux RHEL", "IBM Db2"...) is written to the public
data file. Exact versions and product filters never leave the collector.

Per platform the "source" picks the vendor feed:
  msrc    Microsoft's monthly security update (CVRF), filtered by product name
  redhat  Red Hat Security Data API, filtered by product
  aix     IBM's AIX advisory folder (aix.software.ibm.com/aix/efixes/security)
  cisco   Cisco's security advisory RSS feed, filtered by a regex on title and text
  nvd     NVD keyword search, filtered by a regex on the CVE description
Every CVE then gets a CVSS score, an EPSS score, a CISA KEV check and a priority.
"""
import json
import os
import re
import time
from datetime import datetime, timedelta, timezone

import fetch

HERE = os.path.dirname(os.path.abspath(__file__))
LOCAL = os.path.join(HERE, "inventory.local.json")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
WINDOW_DAYS = 62          # about two monthly patch cycles
KEEP_DAYS = 120           # items stay listed this long after release
MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def load_inventory():
    raw = os.environ.get("PATCH_INVENTORY")
    if raw and raw.strip():
        return json.loads(raw)
    if os.path.exists(LOCAL):
        return json.load(open(LOCAL, encoding="utf-8"))
    return None


# ---------- priority: same rules as the old tracker ----------
def sev_rating(score):
    if score is None:
        return ""
    return "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low"


def exploit_rating(epss):
    if epss is None:
        return ""
    return "High" if epss >= 0.5 else "Medium" if epss >= 0.1 else "Low"


def priority(score, epss, exploited):
    """CVSS severity x EPSS likelihood. A flaw known to be exploited is always Critical."""
    if exploited:
        return "Critical"
    s, e = sev_rating(score), exploit_rating(epss)
    if not s:
        return ""
    e = e or "Low"
    if s == "Critical" and e == "High":
        return "Critical"
    if (s == "Critical" and e == "Medium") or (s == "High" and e == "High"):
        return "High"
    if (s == "Critical" and e == "Low") or (s == "High") or (s == "Medium" and e in ("High", "Medium")):
        return "Medium"
    return "Low"


# ---------- vendor sources ----------
def _iso(d):
    return d.astimezone(timezone.utc).date().isoformat() if d else ""


def src_msrc(p, since, now):
    """Microsoft: CVEs rated (at least) p['min'] on a product whose name matches p['products']."""
    months = sorted({(now - timedelta(days=d)).strftime("%Y-%b") for d in (0, 31, WINDOW_DAYS)})
    rx = re.compile(p.get("products", "^Windows Server"), re.I)
    want = [s.lower() for s in p.get("severities", ["Critical"])]
    out = {}
    for m in months:
        try:
            d = fetch.get_json(f"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{m}", f"msrc-{m}",
                               headers={"Accept": "application/json"}, timeout=120)
        except fetch.FetchError as e:
            if "404" in str(e):
                continue  # month not published yet
            raise
        rel = (d.get("DocumentTracking") or {}).get("InitialReleaseDate", "")[:10]
        ids = {x["ProductID"] for x in d["ProductTree"].get("FullProductName", []) if rx.search(x.get("Value", ""))}
        for v in d.get("Vulnerability", []):
            cve = v.get("CVE", "")
            if not cve.startswith("CVE-"):
                continue
            sev = {t["Description"].get("Value", "").lower() for t in v.get("Threats", [])
                   if t.get("Type") == 3 and set(t.get("ProductID", [])) & ids}
            if not sev & set(want):
                continue
            exploited = any(t.get("Type") == 1 and "Exploited:Yes" in (t["Description"].get("Value") or "")
                            for t in v.get("Threats", []))
            score = max([s.get("BaseScore") or 0 for s in v.get("CVSSScoreSets", []) if set(s.get("ProductID", [])) & ids] or [0]) or None
            out[cve] = {"title": (v.get("Title") or {}).get("Value", ""), "pub": rel, "cvss": score, "ver": "3.1" if score else "",
                        "vsev": "Critical" if "critical" in sev else sorted(sev)[0].title(), "applies": "yes",
                        "link": f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}", "adv": f"{m} update",
                        "vexp": exploited}
    return out, []


def src_redhat(p, since, now):
    """Red Hat: CVEs of the given severity for each product name in p['products']."""
    out = {}
    for prod in p.get("products", []):
        for sev in p.get("severities", ["critical"]):
            url = ("https://access.redhat.com/hydra/rest/securitydata/cve.json?per_page=500"
                   f"&after={since.date().isoformat()}&severity={sev}&product={fetch.urllib.parse.quote(prod)}")
            for r in fetch.get_json(url, f"redhat-{prod}-{sev}".replace(" ", "_")):
                cve = r.get("CVE", "")
                if not cve or not r.get("advisories"):
                    continue  # no fix shipped yet for this product
                score = float(r["cvss3_score"]) if r.get("cvss3_score") else None
                adv = sorted(r["advisories"])[-1]
                out.setdefault(cve, {"title": r.get("bugzilla_description", ""), "pub": (r.get("public_date") or "")[:10],
                                     "cvss": score, "ver": "3.1" if score else "", "vsev": sev.title(), "applies": "yes",
                                     "link": f"https://access.redhat.com/security/cve/{cve}", "adv": adv})
    return out, []


AIX_ROW = re.compile(r'href="([a-z0-9_]+_advisory\d*\.asc)">[^<]*</a>\s+(\d{4}-\d{2}-\d{2})')


def src_aix(p, since, now):
    """IBM AIX/VIOS: advisories published in the window; 'applies' is yes when the text names our level."""
    base = "https://aix.software.ibm.com/aix/efixes/security/"
    listing = fetch.get(base, "aix-index")
    mine = re.compile(p.get("match", r"7\.2"), re.I)
    out, check = {}, []
    for name, d in AIX_ROW.findall(listing):
        if d < since.date().isoformat():
            continue
        txt = fetch.get(base + name, "aix-" + name)
        title = re.search(r"Security Bulletin:\s*(.+)", txt)
        title = title.group(1).strip() if title else name
        applies = "yes" if mine.search(txt.split("AFFECTED PRODUCTS", 1)[-1][:3000]) else "check"
        blocks = re.split(r"\n\s*CVEID:\s*", txt)[1:]
        if not blocks:
            check.append({"title": title, "link": base + name, "issue": "No CVE listed - read the advisory"})
        for b in blocks:
            cve = CVE_RE.search(b)
            if not cve:
                continue
            sc = re.search(r"CVSS Base Score:\s*([\d.]+)", b)
            desc = re.search(r"DESCRIPTION:\s*(.+?)(?:\n\s*CVSS|\Z)", b, re.S)
            out.setdefault(cve.group(0).upper(), {
                "title": title, "pub": d, "cvss": float(sc.group(1)) if sc else None, "ver": "3.1" if sc else "",
                "desc": re.sub(r"\s+", " ", desc.group(1)).strip()[:300] if desc else "", "applies": applies,
                "link": base + name, "adv": name.replace(".asc", "")})
    return out, check


def src_cisco(p, since, now):
    """Cisco: advisories in the RSS feed whose title or summary matches p['match']."""
    rx = re.compile(p.get("match", r"NX-OS|Nexus 9000"), re.I)
    out, check = {}, []
    for it in fetch.parse_feed(fetch.get("https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml", "cisco-rss")):
        if it["date"] and it["date"] < since:
            continue
        if not rx.search(it["title"] + " " + it["summary"]):
            continue
        link = it["link"].split("?")[0]
        adv = link.rstrip("/").rsplit("/", 1)[-1]
        cves = sorted({c.upper() for c in CVE_RE.findall(it["summary"])})
        if not cves:
            check.append({"title": it["title"], "link": link, "issue": "CVE IDs are on the advisory page", "d": _iso(it["date"])})
        crit = "Critical" if re.search(r"\bcritical\b", it["summary"], re.I) else ""
        for c in cves:
            out.setdefault(c, {"title": it["title"], "pub": _iso(it["date"]), "cvss": None, "ver": "", "vsev": crit,
                               "applies": "check", "link": link, "adv": adv})
    return out, check


def src_nvd(p, since, now):
    """NVD keyword search; keeps CVEs whose description matches p['match'] (our version)."""
    key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": key} if key else {}
    s = since.strftime("%Y-%m-%dT00:00:00.000Z")
    e = now.astimezone(timezone.utc).strftime("%Y-%m-%dT23:59:59.999Z")
    url = ("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=500"
           f"&keywordSearch={fetch.urllib.parse.quote(p['keyword'])}&pubStartDate={s}&pubEndDate={e}")
    d = fetch.get_json(url, "nvdkw-" + re.sub(r"\W+", "_", p["keyword"]), headers=headers, tries=3)
    if not fetch.FIXTURES:
        time.sleep(0.8 if key else 6.5)
    mine = re.compile(p["match"], re.I) if p.get("match") else None
    src_rx = re.compile(p["source_id"], re.I) if p.get("source_id") else None
    out = {}
    for v in d.get("vulnerabilities", []):
        c = v["cve"]
        desc = next((x["value"] for x in c.get("descriptions", []) if x.get("lang") == "en"), "")
        if mine and not mine.search(desc):
            continue
        if src_rx and not src_rx.search(c.get("sourceIdentifier", "")):
            continue
        score, ver = _nvd_score(c.get("metrics", {}))
        refs = [r["url"] for r in c.get("references", []) if any(h in r["url"] for h in p.get("advisory_hosts", []))]
        out[c["id"]] = {"title": "", "desc": desc[:300], "pub": c.get("published", "")[:10], "cvss": score, "ver": ver,
                        "applies": "yes" if mine else "check",
                        "link": refs[0] if refs else f"https://nvd.nist.gov/vuln/detail/{c['id']}", "adv": ""}
    return out, []


def _nvd_score(m):
    for k, ver in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
        if m.get(k):
            prim = [x for x in m[k] if x.get("type") == "Primary"] or m[k]
            return float(prim[0]["cvssData"]["baseScore"]), ver
    return None, ""


SOURCES = {"msrc": src_msrc, "redhat": src_redhat, "aix": src_aix, "cisco": src_cisco, "nvd": src_nvd}
SOURCE_NAMES = {"msrc": "Patch: Microsoft MSRC", "redhat": "Patch: Red Hat security data",
                "aix": "Patch: IBM AIX advisories", "cisco": "Patch: Cisco advisories", "nvd": "Patch: NVD keyword search"}


# ---------- the run ----------
def run(R):
    """R is the Run object from run.py (for D, ok/failed tracking, dates)."""
    inv = load_inventory()
    P = R.D.setdefault("patch", {})
    if not inv:
        P["configured"] = False
        return
    P["configured"] = True
    now = R.now.astimezone(timezone.utc)
    since = now - timedelta(days=WINDOW_DAYS)
    prev = {(i["cve"], i["plat"]): i for i in P.get("items", [])}
    items, check, plats = [], [], []
    for p in inv.get("platforms", inv if isinstance(inv, list) else []):
        name, kind = p["name"], p["source"]
        plats.append(name)
        srcname = SOURCE_NAMES.get(kind, "Patch: " + kind)
        src = {"n": srcname}
        got = R.track(src, lambda p=p, kind=kind: SOURCES[kind](p, since, now))
        if got is None:
            # feed down tonight: keep what we had for this platform
            items += [i for i in P.get("items", []) if i["plat"] == name]
            check += [c for c in P.get("check", []) if c["plat"] == name]
            continue
        found, chk = got
        min_cvss = p.get("min_cvss")
        for cve, r in found.items():
            if r.get("pub") and r["pub"] < since.date().isoformat():
                continue  # older release cycle
            old = prev.get((cve, name), {})
            it = {"cve": cve, "plat": name, "t": (r.get("title") or r.get("desc") or "")[:160],
                  "pub": r.get("pub") or old.get("pub") or R.ts, "first": old.get("first") or R.ts,
                  "cvss": r.get("cvss") if r.get("cvss") is not None else old.get("cvss"),
                  "ver": r.get("ver") or old.get("ver", ""), "vsev": r.get("vsev", ""), "applies": r.get("applies", "check"),
                  "link": r.get("link", ""), "adv": r.get("adv", ""), "vexp": bool(r.get("vexp")),
                  "epss": old.get("epss"), "epss_prev": old.get("epss")}
            if r.get("desc") and r.get("title"):
                it["d"] = r["desc"][:240]
            if min_cvss and it["cvss"] is not None and it["cvss"] < min_cvss and it["vsev"] != "Critical":
                continue
            items.append(it)
        for c in chk:
            c["plat"] = name
            check.append(c)
    # drop items released too long ago
    cut = (now - timedelta(days=KEEP_DAYS)).date().isoformat()
    items = [i for i in items if i["pub"] >= cut]
    # CVSS from NVD for the ones still missing a score (rate-limited, a few per night)
    missing = [i for i in items if i["cvss"] is None and not fetch.FIXTURES][:25]
    for i in missing:
        try:
            i["cvss"], i["ver"] = fetch.nvd_score(i["cve"])
        except Exception:
            pass
        time.sleep(0.8 if os.environ.get("NVD_API_KEY") else 6.5)
    # EPSS for all
    scores = fetch.epss([i["cve"] for i in items]) if items else {}
    for i in items:
        if i["cve"] in scores:
            i["epss"] = round(scores[i["cve"]][0], 4)
    # exploited? CISA KEV, or the vendor says so
    kev = {k["cve"]: k for k in R.D.get("kev", [])}
    inc_by_cve = {}
    for x in R.D.get("incidents", []):
        for c in CVE_RE.findall((x.get("cve") or "") + " " + x.get("sum", "")):
            inc_by_cve.setdefault(c.upper(), x["id"])
    for i in items:
        k = kev.get(i["cve"])
        i["kev"] = bool(k)
        if k:
            i["due"] = k.get("d", "")
            i["rw"] = bool(k.get("rw"))
        if k and k.get("link"):
            i["inc"] = k["link"]
        elif i["cve"] in inc_by_cve:
            i["inc"] = inc_by_cve[i["cve"]]
        i["prio"] = priority(i["cvss"], i["epss"], i["kev"] or i["vexp"])
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "": 4}
    items.sort(key=lambda i: (order[i["prio"]], -(i["cvss"] or 0), -(i["epss"] or 0)))
    platforms = inv.get("platforms", inv if isinstance(inv, list) else [])
    # public: which feed covers each platform, and a product-name pattern (no versions) to spot news about it
    src = {p["name"]: p["source"] for p in platforms}
    news = {p["name"]: p.get("news") or re.escape(p["name"]) for p in platforms}
    P.update(updated=R.ts, window=[since.date().isoformat(), now.date().isoformat()], platforms=plats, items=items, check=check,
             src=src, news=news)
    # daily counts per priority, for the trend chart
    hist = P.setdefault("history", {})
    hist[R.ts] = {k: sum(1 for i in items if i["prio"] == k) for k in ("Critical", "High", "Medium", "Low")}
    hist[R.ts]["kev"] = sum(1 for i in items if i["kev"])
    for d in sorted(hist)[:-120]:
        del hist[d]
