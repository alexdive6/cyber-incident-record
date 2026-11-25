"""Network access and feed parsing. Standard library only.

Set CIR_FIXTURES=<folder> to read saved responses instead of the network
(used by the offline test): each request is answered by <folder>/<key>.*.
"""
import email.utils
import gzip
import html
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

CONTACT = os.environ.get("CONTACT_EMAIL") or "set-CONTACT_EMAIL@example.com"
UA = f"CyberIncidentRecord/1.0 (+public dashboard; contact {CONTACT})"
FIXTURES = os.environ.get("CIR_FIXTURES")


class FetchError(Exception):
    pass


def get(url, key, headers=None, data=None, tries=3, timeout=40):
    """Return the response body as text. key names the fixture file in test mode."""
    if FIXTURES:
        for ext in (".json", ".xml", ".txt"):
            p = os.path.join(FIXTURES, key + ext)
            if os.path.exists(p):
                with open(p, encoding="utf-8") as f:
                    return f.read()
        raise FetchError(f"no fixture for {key}")
    h = {"User-Agent": UA, "Accept": "*/*", "Accept-Encoding": "gzip"}
    h.update(headers or {})
    last = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers=h, data=data)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                if r.headers.get("Content-Encoding") == "gzip":
                    raw = gzip.decompress(raw)
                return raw.decode(r.headers.get_content_charset() or "utf-8", errors="replace")
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last = e
            code = getattr(e, "code", None)
            if code in (401, 403, 404, 410):
                break
            time.sleep(2 * (i + 1) ** 2)
    raise FetchError(f"{url}: {last}")


def get_json(url, key, **kw):
    return json.loads(get(url, key, **kw))


# ---------------- RSS / Atom ----------------
TAG_RE = re.compile(r"<[^>]+>")


def clean(text, limit=420):
    t = html.unescape(TAG_RE.sub(" ", text or ""))
    t = re.sub(r"\s+", " ", t).strip()
    t = re.sub(r"(The post .*? appeared first on .*)$", "", t).strip()
    if len(t) > limit:
        cut = t[:limit].rsplit(" ", 1)[0]
        t = cut.rstrip(",;:") + "…"
    return t


def _date(s):
    if not s:
        return None
    s = s.strip()
    try:
        d = email.utils.parsedate_to_datetime(s)
    except (TypeError, ValueError):
        d = None
    if d is None:
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc)


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def parse_feed(text):
    """Parse RSS 2.0, RSS 1.0 (RDF) or Atom into a list of items."""
    text = re.sub(r"^\s*<\?xml[^>]*\?>", "", text.lstrip("﻿"))
    root = ET.fromstring(text)
    out = []
    for el in root.iter():
        name = _local(el.tag)
        if name not in ("item", "entry"):
            continue
        it = {"title": "", "link": "", "date": None, "summary": ""}
        for c in el:
            n = _local(c.tag)
            if n == "title":
                it["title"] = clean(c.text or "", 300)
            elif n == "link":
                href = c.get("href")
                if href and (c.get("rel") in (None, "alternate")):
                    it["link"] = href
                elif c.text and not it["link"]:
                    it["link"] = c.text.strip()
            elif n in ("pubDate", "published", "updated", "date", "issued") and not it["date"]:
                it["date"] = _date(c.text)
            elif n in ("description", "summary", "encoded", "content") and not it["summary"]:
                it["summary"] = clean("".join(c.itertext()) if len(c) else (c.text or ""))
            elif n == "guid" and not it["link"] and (c.text or "").startswith("http"):
                it["link"] = c.text.strip()
        if it["title"] and it["link"]:
            out.append(it)
    return out


# ---------------- APIs ----------------
def kev(url):
    return get_json(url, "kev").get("vulnerabilities", [])


def euvd_exploited(url):
    d = get_json(url, "euvd")
    return d if isinstance(d, list) else d.get("items", [])


def epss(cves):
    """{cve: (score, percentile)} for up to a few hundred CVEs, 100 per call."""
    res = {}
    cves = sorted(set(cves))
    for i in range(0, len(cves), 100):
        chunk = cves[i:i + 100]
        url = "https://api.first.org/data/v1/epss?cve=" + ",".join(chunk)
        try:
            d = get_json(url, f"epss{i // 100}" if FIXTURES else "epss")
        except FetchError:
            continue
        for r in d.get("data", []):
            res[r["cve"]] = (float(r["epss"]), float(r["percentile"]))
    return res


def nvd_cve(cve):
    """{score, ver, pub} for one CVE from NVD: best CVSS base score (v4, then v3.1, then v3.0) and publish date."""
    key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": key} if key else {}
    d = get_json("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve, "nvd-" + cve, headers=headers, tries=2)
    vulns = d.get("vulnerabilities") or []
    if not vulns:
        return {"score": None, "ver": "", "pub": ""}
    c = vulns[0]["cve"]
    m = c.get("metrics", {})
    out = {"score": None, "ver": "", "pub": c.get("published", "")[:10]}
    for k, ver in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
        if m.get(k):
            prim = [x for x in m[k] if x.get("type") == "Primary"] or m[k]
            out.update(score=float(prim[0]["cvssData"]["baseScore"]), ver=ver)
            break
    return out


def nvd_cvss(cve):
    return nvd_cve(cve)["score"]


def nvd_score(cve):
    r = nvd_cve(cve)
    return r["score"], r["ver"]


def ransomware_recent(url):
    d = get_json(url, "ransomware")
    return d if isinstance(d, list) else d.get("data", [])


def sec_item105(days_back, today):
    """8-K filings mentioning Item 1.05 in the last few days (SEC full-text search)."""
    start = (today.toordinal() - days_back)
    from datetime import date
    s = date.fromordinal(start).isoformat()
    url = ("https://efts.sec.gov/LATEST/search-index?q=%22Item%201.05%22&forms=8-K"
           f"&dateRange=custom&startdt={s}&enddt={today.isoformat()}")
    d = get_json(url, "sec")
    hits = d.get("hits", {}).get("hits", [])
    out = []
    for h in hits:
        src = h.get("_source", {})
        names = src.get("display_names") or []
        adsh = h.get("_id", "").split(":")[0]
        ciks = src.get("ciks") or [""]
        link = ""
        if adsh and ciks[0]:
            link = f"https://www.sec.gov/Archives/edgar/data/{int(ciks[0])}/{adsh.replace('-', '')}/{adsh}-index.html"
        out.append({"company": re.sub(r"\s*\(CIK.*$", "", names[0]) if names else "Unknown company",
                    "date": src.get("file_date"), "link": link})
    return out


def hibp_breaches(url):
    return get_json(url, "hibp")


def anthropic(prompt, system, model, max_tokens=4000):
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None
    body = json.dumps({"model": model, "max_tokens": max_tokens, "system": system,
                       "messages": [{"role": "user", "content": prompt}]}).encode()
    txt = get("https://api.anthropic.com/v1/messages", "anthropic",
              headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
              data=body, tries=2, timeout=180)
    d = json.loads(txt)
    return "".join(b.get("text", "") for b in d.get("content", []) if b.get("type") == "text")
