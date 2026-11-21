"""Nightly run: read the sources, update site/data/latest.json, archive a snapshot.

    python collector/run.py            normal run
    CIR_FIXTURES=tests/fixtures python collector/run.py   offline test

Optional environment variables (GitHub repository secrets):
    ANTHROPIC_API_KEY  lets Claude write the titles, summaries and month notes
    NVD_API_KEY        faster CVSS lookups from NIST
    CONTACT_EMAIL      sent in the User-Agent; the SEC asks for one
"""
import hashlib
import json
import os
import re
import sys
import time
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

sys.path.insert(0, os.path.dirname(__file__))
import fetch  # noqa: E402
import rules  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE = os.path.join(ROOT, "site")
LATEST = os.path.join(SITE, "data", "latest.json")
CFG = json.load(open(os.path.join(ROOT, "collector", "sources.json"), encoding="utf-8"))
OVR_PATH = os.path.join(ROOT, "collector", "overrides.json")
TZ = ZoneInfo(CFG.get("timezone", "America/New_York"))
MODEL = os.environ.get("CLAUDE_MODEL") or "claude-haiku-5-5"
MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]
SEVR = {"crit": 0, "high": 1, "med": 2}


def log(*a):
    print(*a, flush=True)


def fmt(iso):
    d = date.fromisoformat(iso[:10])
    return f"{d.day} {MON[d.month - 1]}"


def slug(text, iso):
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return "-".join(s.split("-")[:5]) + "-" + iso[5:10].replace("-", "")


def ref_id(url):
    return "r" + hashlib.sha1(url.encode()).hexdigest()[:10]


class Run:
    def __init__(self):
        self.now = datetime.now(TZ)
        self.today = self.now.date()
        self.ts = self.today.isoformat()
        self.D = json.load(open(LATEST, encoding="utf-8"))
        self.ok, self.failed = [], []
        self.new_ids, self.upd_ids, self.kev_new = [], [], []
        prev = self.D["meta"].get("compiled")
        try:
            last = datetime.fromisoformat(prev)
        except (TypeError, ValueError):
            last = self.now - timedelta(days=2)
        # read news from the last run minus a 6 h overlap, at least 30 h, at most 7 days
        since = min(last - timedelta(hours=6), self.now - timedelta(hours=30))
        self.since = max(since, self.now - timedelta(days=7)).astimezone(timezone.utc)

    # ---------- helpers ----------
    def track(self, src, fn):
        try:
            r = fn()
            if src["n"] not in self.ok:
                self.ok.append(src["n"])
            return r
        except Exception as e:  # one bad feed never stops the run
            self.failed.append({"n": src["n"], "err": str(e)[:160]})
            log("  FAILED", src["n"], "-", str(e)[:160])
            return None

    def ref(self, label, url):
        rid = ref_id(url)
        self.D["refs"].setdefault(rid, [label[:110], url])
        return rid

    def incident(self, iid):
        return next((x for x in self.D["incidents"] if x["id"] == iid), None)

    # ---------- 1. CISA KEV + EPSS + CVSS + EUVD ----------
    def vulns(self):
        src = next(s for s in CFG["sources"] if s.get("kind") == "kev")
        rows = self.track(src, lambda: fetch.kev(src["url"]))
        start = max(self.D["meta"]["from"], (self.today - timedelta(days=400)).isoformat())
        old = {k["cve"]: k for k in self.D["kev"]}
        if rows is not None:
            kev = []
            for v in rows:
                if v.get("dateAdded", "") < start:
                    continue
                cve = v["cveID"]
                r = dict(old.get(cve, {}))
                name = v.get("vulnerabilityName", "")
                for pre in (v.get("vendorProject", ""), v.get("product", "")):
                    if pre and name.lower().startswith(pre.lower()):
                        name = name[len(pre):].strip()
                name = re.sub(r"\s*Vulnerability$", "", name).strip() or v.get("vulnerabilityName", "")
                r.update(cve=cve, v=v.get("vendorProject", ""), p=v.get("product", ""), n=name,
                         a=v["dateAdded"], d=v.get("dueDate", ""), rw=v.get("knownRansomwareCampaignUse") == "Known",
                         desc=fetch.clean(v.get("shortDescription", ""), 400), act=fetch.clean(v.get("requiredAction", ""), 300))
                r.setdefault("link", "")
                if cve not in old:
                    self.kev_new.append(cve)
                kev.append(r)
            # keep EUVD-only rows from earlier nights
            kev += [k for k in self.D["kev"] if k.get("src") == "EUVD" and k["cve"] not in {x["cve"] for x in kev}]
            self.D["kev"] = kev
        # EUVD: exploited in the EU but not (yet) in KEV
        eu = next((s for s in CFG["sources"] if s.get("kind") == "euvd"), None)
        if eu:
            items = self.track(eu, lambda: fetch.euvd_exploited(eu["url"])) or []
            have = {k["cve"] for k in self.D["kev"]}
            for it in items:
                cves = [c.upper() for c in rules.CVE_RE.findall(str(it.get("aliases", "")))]
                if not cves or cves[0] in have:
                    continue
                try:
                    since = datetime.strptime(it.get("exploitedSince", "")[:12].strip().rstrip(","), "%b %d, %Y").date()
                except ValueError:
                    continue
                if since < self.today - timedelta(days=30):
                    continue
                ven = ((it.get("enisaIdVendor") or [{}])[0].get("vendor") or {}).get("name", "")
                prod = ((it.get("enisaIdProduct") or [{}])[0].get("product") or {}).get("name", "")
                self.D["kev"].append({"cve": cves[0], "v": ven, "p": prod, "n": "Exploited flaw (ENISA)", "desc": fetch.clean(it.get("description", ""), 400),
                                      "a": since.isoformat(), "d": "", "src": "EUVD", "link": "",
                                      "cvss": it.get("baseScore") or None})
                self.kev_new.append(cves[0])
                have.add(cves[0])
        # EPSS for recent flaws and the watch list
        recent = [k["cve"] for k in self.D["kev"] if k["a"] >= (self.today - timedelta(days=90)).isoformat() and k["cve"].startswith("CVE-")]
        recent += [c[0] for w in self.D.get("watch", []) for c in (w.get("cves") or [])]
        ep_src = next((s for s in CFG["sources"] if s.get("kind") == "epss"), {"n": "FIRST EPSS"})
        scores = self.track(ep_src, lambda: fetch.epss(recent)) or {}
        for k in self.D["kev"]:
            if k["cve"] in scores:
                k["epss"] = round(scores[k["cve"]][0], 4)
        # CVSS from NVD where missing (rate-limited, so a handful per night)
        nvd_src = next((s for s in CFG["sources"] if s.get("kind") == "nvd"), {"n": "NVD"})
        missing = [k for k in sorted(self.D["kev"], key=lambda k: k["a"], reverse=True) if k.get("cvss") is None and k["cve"].startswith("CVE-")][:20]
        pause = 0.8 if os.environ.get("NVD_API_KEY") else 6.5
        got, errs = 0, []
        for k in missing:
            try:
                score = fetch.nvd_cvss(k["cve"])
                got += 1
                if score is not None:
                    k["cvss"] = score
            except Exception as e:
                errs.append(str(e))
            if not fetch.FIXTURES:
                time.sleep(pause)
        if missing and not got:
            self.failed.append({"n": nvd_src["n"], "err": (errs or ["no answer"])[0][:160]})
        elif missing:
            self.ok.append(nvd_src["n"])
        self.D["kev"].sort(key=lambda k: (k["a"], k["cve"]), reverse=True)

    def kev_incidents(self):
        """Turn tonight's new KEV additions into 'Exploited flaw' entries, one per vendor+product+day."""
        groups = {}
        for k in self.D["kev"]:
            if k["cve"] in self.kev_new and not k.get("link"):
                groups.setdefault((k["v"], k["p"], k["a"]), []).append(k)
        kev_ref = self.ref("CISA Known Exploited Vulnerabilities catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
        for (v, p, a), ks in groups.items():
            # already covered by an entry that names the CVE?
            hit = next((x for x in self.D["incidents"] if any(k["cve"] in (x.get("cve") or "") for k in ks)), None)
            if hit:
                for k in ks:
                    k["link"] = hit["id"]
                if kev_ref not in hit["s"]:
                    hit["s"].append(kev_ref)
                    hit["tl"].append([fmt(a), "Added to CISA's exploited list."])
                    hit["updated"] = self.ts
                    self.upd_ids.append(hit["id"])
                continue
            cvss = max([k["cvss"] for k in ks if k.get("cvss") is not None], default=None)
            eu_only = all(k.get("src") == "EUVD" for k in ks)
            text = " ".join(k.get("desc", "") + " " + k["n"] for k in ks)
            sec_text = f"{v} {p} {text}"
            x = {"id": slug(f"{v} {p}", a), "k": "flaw", "t": f"{v} {p}: {ks[0]['n']}".strip(),
                 "cve": " · ".join(k["cve"] for k in ks) + (f" · CVSS {cvss:.1f}" if cvss else ""),
                 "sev": rules.severity_flaw(cvss), "iso": a, "when": fmt(a), "e": "flaw",
                 # backfilled flaws (first run, or a feed that was down) keep their own date so they don't flood "New"
                 "added": self.ts if a >= (self.today - timedelta(days=3)).isoformat() else a,
                 "tags": [t for t in rules.tags_for(sec_text, "X", "flaw") if t in ("mail", "state", "ransom", "ai")],
                 "sec": "X", "reg": "GLOBAL", "conf": "confirmed",
                 "sum": " ".join(k.get("desc", "") for k in ks)[:600] or f"{v} {p}: exploited in the wild.",
                 "how": "Exploited in the wild, per ENISA." if eu_only else "Exploited in the wild, per CISA.",
                 "tl": [[fmt(a), "Added to ENISA's exploited list." if eu_only else "Added to CISA's exploited list."]] +
                       ([[fmt(ks[0]["d"]), "CISA deadline for US federal agencies."]] if ks[0].get("d") else []),
                 "fix": ks[0].get("act") or "Apply the vendor's fix.",
                 "s": [kev_ref] if not eu_only else [self.ref("ENISA EUVD", "https://euvd.enisa.europa.eu/")]}
            if any(k.get("rw") for k in ks):
                x["tags"].append("ransom")
            while self.incident(x["id"]):
                x["id"] += "x"
            self.D["incidents"].append(x)
            self.new_ids.append(x["id"])
            for k in ks:
                k["link"] = x["id"]

    # ---------- 2. RSS feeds ----------
    def feeds(self):
        items = []
        for src in CFG["sources"]:
            if src.get("kind") != "rss":
                continue
            # "feeds" is a list of feed URLs for multi-feed sources; elsewhere it is
            # a display label ("what this source feeds on the page"), so ignore strings.
            urls = src.get("feeds") if isinstance(src.get("feeds"), list) else [src["url"]]
            for i, url in enumerate(urls):
                key = src["id"] + (f"-{i}" if i else "")
                parsed = self.track(src, lambda u=url, k=key: fetch.parse_feed(fetch.get(u, k)))
                for it in parsed or []:
                    if it["date"] and it["date"] < self.since:
                        continue
                    if src.get("filter") and not re.search(src["filter"], it["title"], re.I):
                        continue
                    it["src"] = src
                    items.append(it)
        seen, out = set(), []
        for it in items:
            if it["link"] in seen:
                continue
            seen.add(it["link"])
            out.append(it)
        log(f"  {len(out)} feed items since {self.since:%Y-%m-%d %H:%M} UTC")
        return out

    def advisories(self, items):
        adv = {a.get("url") or self.D["refs"].get(a["s"], ["", ""])[1]: a for a in self.D.get("advisories", [])}
        for it in items:
            if it["src"].get("role") != "advisory":
                continue
            rid = self.ref(f"{it['src']['short']}: {it['title']}", it["link"])
            d = (it["date"] or self.now).astimezone(TZ).date().isoformat()
            adv.setdefault(it["link"], {"d": d, "org": it["src"]["short"], "t": it["title"], "s": rid, "url": it["link"]})
        cutoff = (self.today - timedelta(days=45)).isoformat()
        self.D["advisories"] = sorted([a for a in adv.values() if a["d"] >= cutoff], key=lambda a: a["d"], reverse=True)[:40]

    # ---------- 3. Other incident sources ----------
    def extra_items(self):
        out = []
        for src in CFG["sources"]:
            kind = src.get("kind")
            if kind == "sec":
                rows = self.track(src, lambda: fetch.sec_item105(3, self.today)) or []
                for r in rows:
                    if not r["link"]:
                        continue
                    out.append({"title": f"{r['company']} reports a material cybersecurity incident to the SEC",
                                "summary": f"{r['company']} filed a Form 8-K under Item 1.05, the item US-listed companies use for a cybersecurity incident they judge material.",
                                "link": r["link"], "date": datetime.fromisoformat(r["date"]).replace(tzinfo=timezone.utc) if r.get("date") else self.now,
                                "src": src, "victim": r["company"], "confirmed": True, "floor": "high"})
            elif kind == "hibp":
                rows = self.track(src, lambda: fetch.hibp_breaches(src["url"])) or []
                for b in rows:
                    added = fetch._date(b.get("AddedDate"))
                    if not added or added < self.since:
                        continue
                    n = b.get("PwnCount", 0)
                    out.append({"title": f"{b.get('Title', b.get('Name'))}: {n:,} accounts in a verified breach",
                                "summary": fetch.clean(b.get("Description", ""), 380) + f" Data: {', '.join(b.get('DataClasses', [])[:6])}.",
                                "link": f"https://haveibeenpwned.com/Breach/{b.get('Name')}", "date": added, "src": src,
                                "victim": b.get("Title"), "records_m": n / 1e6, "confirmed": True})
            elif kind == "ransomware":
                rows = self.track(src, lambda: fetch.ransomware_recent(src["url"])) or []
                stats = self.D.setdefault("claimStats", {})
                for v in rows:
                    disc = fetch._date(v.get("discovered") or v.get("published") or v.get("attackdate"))
                    if not disc or disc < self.since:
                        continue
                    ym = disc.astimezone(TZ).strftime("%Y-%m")
                    st = stats.setdefault(ym, {"n": 0, "groups": {}, "seen": []})
                    vid = f"{v.get('group_name') or v.get('group')}|{v.get('victim') or v.get('post_title')}"
                    if vid in st["seen"]:
                        continue
                    st["seen"].append(vid)
                    st["seen"] = st["seen"][-3000:]
                    st["n"] += 1
                    g = v.get("group_name") or v.get("group") or "unknown"
                    st["groups"][g] = st["groups"].get(g, 0) + 1
                    activity = (v.get("activity") or v.get("sector") or "")
                    victim = v.get("victim") or v.get("post_title") or ""
                    if re.search(r"financ|bank|insur|payment", activity, re.I):
                        out.append({"title": f"{victim} listed by the {g} ransomware group",
                                    "summary": f"The {g} group listed {victim} ({activity}, {v.get('country', '')}) on its leak site. Not confirmed by the victim.",
                                    "link": v.get("url") or v.get("post_url") or f"https://www.ransomware.live/group/{g}",
                                    "date": disc, "src": src, "victim": victim, "claim": True})
        return out

    # ---------- 4. Group stories, match to the record, add new entries ----------
    def cluster(self, items):
        cands = []
        for it in items:
            if it.get("victim"):
                cands.append(it)
                continue
            if it["src"].get("role") not in ("news", "research"):
                continue
            text = it["title"] + " " + it["summary"]
            critical_cve = rules.CVE_RE.search(text) and re.search(r"\b(critical|remote code execution|rce)\b", text, re.I)
            if rules.NOT_INCIDENT.search(it["title"]) or not (rules.ATTACK.search(text) or critical_cve):
                continue
            cands.append(it)
        clusters = []
        for it in sorted(cands, key=lambda i: i["date"] or self.now):
            cves = {c.upper() for c in rules.CVE_RE.findall(it["title"] + " " + it["summary"])}
            tk, nm = rules.tokens(it["title"]), rules.names(it["title"]) | ({it["victim"]} if it.get("victim") else set())
            for c in clusters:
                j = rules.jaccard(tk, c["tk"])
                if (cves & c["cves"]) or j >= 0.45 or ((nm & c["names"]) and j >= 0.2):
                    c["items"].append(it)
                    c["cves"] |= cves
                    c["tk"] |= tk
                    c["names"] |= nm
                    break
            else:
                clusters.append({"items": [it], "cves": set(cves), "tk": set(tk), "names": set(nm)})
        log(f"  {len(cands)} attack stories in {len(clusters)} groups")
        return clusters

    def match(self, c):
        horizon = (self.today - timedelta(days=30)).isoformat()
        for x in self.D["incidents"]:
            if x["iso"] < horizon:
                continue
            xc = {v.upper() for v in rules.CVE_RE.findall((x.get("cve") or "") + " " + x["sum"])}
            if c["cves"] & xc:
                return x
            j = rules.jaccard(c["tk"], rules.tokens(x["t"]))
            if j >= 0.4 or ((c["names"] & rules.names(x["t"])) and j >= 0.2):
                return x
        return None

    def build(self, clusters):
        drafts = []
        for c in clusters:
            its = sorted(c["items"], key=lambda i: ("ABC".index(i["src"].get("tier", "C")), i["date"] or self.now))
            text = " ".join(i["title"] + ". " + i["summary"] for i in its)
            srcs = {i["src"]["id"] for i in its}
            refs = [self.ref(f"{i['src']['short']}: {i['title']}", i["link"]) for i in its]
            if all(i.get("claim") for i in its):
                conf = "claim"
            elif any(i["src"].get("tier") == "A" or i.get("confirmed") for i in its) or rules.CONFIRM.search(text):
                conf = "confirmed"
            else:
                conf = "reported"
            x = self.match(c)
            if x:
                fresh = [r for r in refs if r not in x["s"]]
                if not fresh:
                    continue
                x["s"] += fresh
                x["tl"].append([fmt(self.ts), "New reporting: " + its[0]["title"][:140]])
                if {"claim": 0, "reported": 1, "confirmed": 2}[conf] > {"claim": 0, "reported": 1, "confirmed": 2}.get(x.get("conf"), 2):
                    x["conf"] = conf
                x["updated"] = self.ts
                if x["id"] not in self.upd_ids and x["id"] not in self.new_ids:
                    self.upd_ids.append(x["id"])
                continue
            iso = min((i["date"] or self.now).astimezone(TZ).date() for i in its).isoformat()
            exploited_flaw = bool(c["cves"]) and rules.EXPLOITED.search(text)
            critical_patch = bool(c["cves"]) and not exploited_flaw and re.search(r"\b(critical|remote code execution|rce)\b", text, re.I)
            if critical_patch:
                self.watch_candidate(c, its, text, refs)
                continue
            sec = rules.sector(text)
            e = "flaw" if exploited_flaw else rules.entry_method(text)
            d = {"id": slug(its[0]["title"], iso), "k": "flaw" if exploited_flaw else "inc", "t": its[0]["title"],
                 "sev": rules.severity_incident(text, sec, conf), "iso": iso, "added": self.ts, "when": fmt(iso),
                 "where": its[0].get("country") or rules.where(text), "e": e, "tags": rules.tags_for(text, sec, e),
                 "sec": "X" if exploited_flaw else sec, "reg": "GLOBAL" if exploited_flaw else rules.region(text),
                 "conf": conf, "sum": max((i["summary"] for i in its), key=len) or its[0]["title"],
                 "how": (self.D["entry"][e] + ".") if e != "undisc" else "Not disclosed.",
                 "tl": [[fmt((i["date"] or self.now).astimezone(TZ).date().isoformat()), "Reported by " + i["src"]["short"]] for i in its][:6],
                 "fix": "Under investigation.", "s": refs, "_text": text[:3000]}
            if any(i.get("floor") == "high" for i in its) and d["sev"] == "med":
                d["sev"] = "high"
            if exploited_flaw:
                d["cve"] = " · ".join(sorted(c["cves"]))[:120]
                d["sev"] = "crit" if re.search(r"\bcritical|9\.\d|10\.0\b", text, re.I) else "high"
                d["fix"] = "Check the vendor advisory for the fixed version."
            while self.incident(d["id"]) or any(o["id"] == d["id"] for o in drafts):
                d["id"] += "x"
            drafts.append(d)
        return drafts

    def watch_candidate(self, c, its, text, refs):
        cves = sorted(c["cves"])
        if any(k["cve"] in cves for k in self.D["kev"]):
            return
        watch = self.D.setdefault("watch", [])
        hit = next((w for w in watch if set(cves) & {x[0] for x in (w.get("cves") or [])} or set(cves) & set(rules.CVE_RE.findall(w.get("cve", "")))), None)
        if hit:
            hit["s"] = list(dict.fromkeys(hit["s"] + refs))
            return
        if len({i["src"]["id"] for i in its}) < 2 and not any(i["src"].get("tier") == "A" for i in its):
            return  # one newsroom alone is not enough for the watch list
        watch.append({"id": slug(its[0]["title"], self.ts), "t": its[0]["title"], "cve": " · ".join(cves[:3]) + (f" +{len(cves) - 3}" if len(cves) > 3 else ""),
                      "d": self.ts, "sev": "crit", "fixed": self.ts if re.search(r"\b(patch\w*|fix\w*|update\w*|releas\w+)\b", text, re.I) else "",
                      "sum": max((i["summary"] for i in its), key=len), "act": "Apply the vendor's fixed version and check which systems run it.",
                      "s": refs, "_text": text[:3000]})

    # ---------- 5. Optional: Claude writes the text ----------
    def refine(self, drafts):
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return drafts
        todo = drafts + [w for w in self.D.get("watch", []) if w.get("_text")]
        if not todo:
            return drafts
        payload = [{"id": d["id"], "kind": "watch" if "act" in d else d["k"], "stories": d["_text"], "draft": {k: d.get(k) for k in ("t", "sev", "sec", "where", "e", "conf")}} for d in todo]
        system = ("You edit a cyber incident dashboard for a bank's office. Use only facts in the stories. Write in plain, short "
                  "sentences, in your own words; never copy sentences from the stories. Reply with JSON only.")
        prompt = ("For each item return an object with: id; keep (false if it is not a real attack, breach, exploited flaw or "
                  "critical fix, or is a duplicate of another item); t (title under 70 characters, victim first); sum (2-3 "
                  "sentences: what happened, who, impact); how (one sentence on how attackers got in, or 'Not disclosed.'); "
                  "fix (one sentence on status or what to do); sev (crit|high|med: crit = money stolen, services halted at a "
                  "bank, hospital or utility, 10m+ records, or critical exploited flaw; high = confirmed breach or any finance "
                  "intrusion; med = claims and small cases); sec (FIN|CRYPTO|RETAIL|HEALTH|GOV|EDU|TECH|TEL|LOG|IND|X); where "
                  "(country, or Global); reg (AMER|EMEA|APAC|GLOBAL); e (social|flaw|cred|third|other|undisc); tags (subset of "
                  "finance,flaw,mail,human,ai,vendor,ransom,state); conf (confirmed|reported|claim).\n\nItems:\n" + json.dumps(payload)[:60000])
        try:
            txt = fetch.anthropic(prompt, system, MODEL, max_tokens=8000)
            m = re.search(r"\[.*\]", txt or "", re.S)
            out = {o["id"]: o for o in json.loads(m.group(0))} if m else {}
            self.ok.append("Claude summaries")
        except Exception as e:
            self.failed.append({"n": "Claude summaries", "err": str(e)[:160]})
            return drafts
        enums = {"sev": SEVR, "sec": self.D["sectors"], "reg": self.D["regions"], "e": self.D["entry"], "conf": {"confirmed": 1, "reported": 1, "claim": 1}}
        kept = []
        for d in todo:
            o = out.get(d["id"])
            if not o:
                if d in drafts:
                    kept.append(d)
                continue
            if o.get("keep") is False:
                if "act" in d:
                    self.D["watch"].remove(d)
                continue
            for f in ("t", "sum", "how", "fix", "where"):
                if isinstance(o.get(f), str) and o[f].strip():
                    d[f] = o[f].strip()
            for f, allowed in enums.items():
                if o.get(f) in allowed:
                    d[f] = o[f]
            if isinstance(o.get("tags"), list):
                d["tags"] = [t for t in o["tags"] if t in self.D["tags"] and t not in ("all", "flaw")]
            if d in drafts:
                kept.append(d)
        return kept

    def month_note(self):
        ym = self.ts[:7]
        L = [x for x in self.D["incidents"] if x["iso"].startswith(ym)]
        if not L:
            return
        notes = self.D.setdefault("monthNotes", {})
        if os.environ.get("ANTHROPIC_API_KEY"):
            lines = "\n".join(f"{x['iso']} [{x['sev']}] [{self.D['sectors'].get(x['sec'], '')}] {x['t']}: {x['sum'][:200]}" for x in sorted(L, key=lambda x: SEVR[x["sev"]])[:80])
            try:
                txt = fetch.anthropic("Entries this month:\n" + lines + "\n\nReturn JSON {\"head\": one sentence, the month's story, under 120 characters, "
                                      "\"pts\": 3 to 4 short sentences with the patterns a bank should act on}. Use only these entries.",
                                      "You write the analyst's note for a cyber incident dashboard. Plain, short sentences. JSON only.", MODEL, 800)
                o = json.loads(re.search(r"\{.*\}", txt, re.S).group(0))
                if o.get("head") and o.get("pts"):
                    notes[ym] = {"head": o["head"], "pts": o["pts"][:4], "auto": True}
                    return
            except Exception as e:
                self.failed.append({"n": "Claude month note", "err": str(e)[:160]})
        if notes.get(ym) and not notes[ym].get("auto"):
            return  # keep a hand-written note
        crit = [x for x in L if x["sev"] == "crit"]
        secs = {}
        for x in L:
            if x["sec"] != "X":
                secs[x["sec"]] = secs.get(x["sec"], 0) + 1
        top = max(secs, key=secs.get) if secs else None
        notes[ym] = {"auto": True,
                     "head": f"{MONTHS[int(ym[5:]) - 1]} so far: {len(L)} entries, {len(crit)} critical" + (f"; most hit: {self.D['sectors'][top].lower()}." if top else "."),
                     "pts": [f"{x['t']} ({fmt(x['iso'])})." for x in sorted(crit, key=lambda x: x["iso"], reverse=True)[:4]] or ["No critical entries yet this month."]}

    # ---------- 6. Act now, housekeeping, write ----------
    def act_now(self):
        cut = (self.today - timedelta(days=21)).isoformat()
        flaws = [x for x in self.D["incidents"] if x["k"] == "flaw" and x["iso"] >= cut]
        crit = sorted([x for x in flaws if x["sev"] == "crit"], key=lambda x: x["iso"], reverse=True)
        high = sorted([x for x in flaws if x["sev"] == "high"], key=lambda x: x["iso"], reverse=True)
        watch = sorted([w for w in self.D.get("watch", []) if w.get("sev") == "crit" and w.get("fixed") and w["d"] >= (self.today - timedelta(days=4)).isoformat()],
                       key=lambda w: w["d"], reverse=True)
        order = [x["id"] for x in crit[:3]] + [w["id"] for w in watch[:1]] + [x["id"] for x in crit[3:]] + [x["id"] for x in high]
        self.D["meta"]["actNow"] = list(dict.fromkeys(order))[:5]

    def housekeeping(self):
        # watch items leave after 21 days, or once the flaw shows up as exploited
        kevs = {k["cve"] for k in self.D["kev"]}
        cut = (self.today - timedelta(days=21)).isoformat()
        self.D["watch"] = [w for w in self.D.get("watch", []) if w["d"] >= cut and not (
            set(rules.CVE_RE.findall(w.get("cve", ""))) | {c[0] for c in (w.get("cves") or [])}) & kevs]
        for w in self.D["watch"]:
            w.pop("_text", None)
        for x in self.D["incidents"]:
            x.pop("_text", None)
        na = self.D.get("notAttacks")
        if na and na.get("until", "9999") < self.ts:
            self.D["notAttacks"] = None
        # move entries older than 400 days out of latest.json
        old_cut = (self.today - timedelta(days=400)).isoformat()
        old = [x for x in self.D["incidents"] if x["iso"] < old_cut]
        if old:
            arch = os.path.join(SITE, "data", "archive", "older.json")
            prev = json.load(open(arch)) if os.path.exists(arch) else []
            json.dump(prev + old, open(arch, "w"), ensure_ascii=False)
            self.D["incidents"] = [x for x in self.D["incidents"] if x["iso"] >= old_cut]
            self.D["ledger"] = [r for r in self.D["ledger"] if r["d"] >= old_cut]
        # drop references nothing points to any more
        used = {s for x in self.D["incidents"] for s in x["s"]} | {s for r in self.D["ledger"] for s in r["s"]}
        used |= {s for w in self.D["watch"] for s in w["s"]} | {a["s"] for a in self.D["advisories"]} | set(self.D.get("kevRefs", []))
        if self.D.get("notAttacks"):
            used |= set(self.D["notAttacks"]["s"])
        self.D["refs"] = {k: v for k, v in self.D["refs"].items() if k in used}

    def overrides(self):
        if not os.path.exists(OVR_PATH):
            return
        o = json.load(open(OVR_PATH, encoding="utf-8"))
        for iid, fields in (o.get("incidents") or {}).items():
            x = self.incident(iid)
            if x:
                x.update(fields)
        hide = set(o.get("hide") or [])
        self.D["incidents"] = [x for x in self.D["incidents"] if x["id"] not in hide]
        if o.get("actNow"):
            self.D["meta"]["actNow"] = o["actNow"]

    def write(self):
        M = self.D["meta"]
        if M.get("edition") != self.ts:
            M["prev"] = M.get("edition", self.ts)
        M["edition"] = self.ts
        M["compiled"] = self.now.isoformat(timespec="minutes")
        M["mode"] = "live"
        nxt = (self.now + timedelta(days=1)).replace(hour=2, minute=0, second=0, microsecond=0)
        M["nextRun"] = nxt.isoformat(timespec="minutes")
        M["health"] = {"ok": len(self.ok), "failed": self.failed, "total": len([s for s in CFG["sources"] if s.get("kind") not in (None, "reference")])}
        M.pop("headlines", None)
        self.D["sources"] = [{k: v for k, v in s.items() if k not in ("feeds", "filter", "id", "short", "role", "kind")} | {"collect": s.get("kind") not in (None, "reference")} for s in CFG["sources"]]
        tmp = LATEST + ".tmp"
        json.dump(self.D, open(tmp, "w", encoding="utf-8"), ensure_ascii=False, indent=0)
        os.replace(tmp, LATEST)
        snap_dir = os.path.join(SITE, "data", "archive", self.ts[:7])
        os.makedirs(snap_dir, exist_ok=True)
        json.dump({"meta": M, "new": self.new_ids, "updated": self.upd_ids, "kevNew": self.kev_new,
                   "entries": [x for x in self.D["incidents"] if x["id"] in self.new_ids + self.upd_ids]},
                  open(os.path.join(snap_dir, self.ts + ".json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        log(f"Done: {len(self.new_ids)} new, {len(self.upd_ids)} updated, {len(self.kev_new)} new exploited flaws, "
            f"{len(self.failed)} feeds failed of {M['health']['total']}")

    def main(self):
        log(f"Run {self.now:%Y-%m-%d %H:%M %Z}")
        self.vulns()
        self.kev_incidents()
        items = self.feeds()
        self.advisories(items)
        items += self.extra_items()
        drafts = self.build(self.cluster(items))
        drafts = self.refine(drafts)
        for d in drafts:
            self.D["incidents"].append(d)
            self.new_ids.append(d["id"])
        self.month_note()
        self.act_now()
        self.housekeeping()
        self.overrides()
        self.write()
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as f:
                f.write(f"### Nightly run {self.ts}\n\n{len(self.new_ids)} new entries, {len(self.upd_ids)} updated, "
                        f"{len(self.kev_new)} new exploited flaws.\n\nFeeds OK: {len(self.ok)}. Failed: {len(self.failed)}\n\n")
                for fl in self.failed:
                    f.write(f"- {fl['n']}: {fl['err']}\n")


if __name__ == "__main__":
    Run().main()
