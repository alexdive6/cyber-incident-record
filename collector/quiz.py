"""Daily quiz: three questions, written once per day into latest.json.

1. One built from the record itself (which software, or how attackers got in).
2. One about a flaw on CISA's exploited list (whose product is it).
3. One concept question: written by Claude when ANTHROPIC_API_KEY is set,
   otherwise taken from collector/quiz_bank.json.
Choices are shuffled with a seed from the date, so the quiz is stable for the day.
"""
import hashlib
import json
import os
import random
import re

import fetch

BANK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quiz_bank.json")
KEEP = 30  # days of past quizzes kept for the archive


def _q(q, right, wrong, why, cat, rnd, ref=None):
    opts = [right] + [w for w in dict.fromkeys(wrong) if w != right][:3]
    if len(opts) < 3:
        return None
    rnd.shuffle(opts)
    out = {"cat": cat, "q": q, "o": opts, "a": opts.index(right), "why": why}
    if ref:
        out["ref"] = ref
    return out


def from_record(D, rnd, ts):
    recent = sorted([x for x in D["incidents"] if x.get("iso", "") >= str(int(ts[:4]) - 1) + ts[4:]],
                    key=lambda x: x["iso"], reverse=True)[:60]
    sws = list(dict.fromkeys(x["sw"] for x in D["incidents"] if x.get("sw") and len(x["sw"]) < 60))
    def why(x):
        how = (x.get("how") or "").strip()
        generic = not how or how.rstrip(".") in D["entry"].values() or how.startswith("Not disclosed")
        return x["sum"][:260] if generic else how

    year = [x for x in D["incidents"] if x.get("iso", "") >= str(int(ts[:4]) - 1) + ts[4:]]
    pool = [x for x in year if x.get("k") == "inc" and x.get("sw") and len(x["sw"]) < 60 and x.get("co")]
    rnd.shuffle(pool)
    for x in pool:
        wrong = rnd.sample([s for s in sws if s != x["sw"]], k=min(3, len(sws) - 1))
        q = _q(f"Which software or service was abused in this incident: \"{x['t']}\"?", x["sw"], wrong,
               f"{x['co']}: {why(x)}", "From the record", rnd, x["id"])
        if q:
            return q
    # fall back to "how did they get in"
    ent = {k: v for k, v in D["entry"].items() if k != "undisc"}
    pool = [x for x in recent if x.get("e") in ent and x.get("co")]
    if pool:
        x = rnd.choice(pool)
        return _q(f"How did attackers get in at {x['co']}?", ent[x["e"]], [v for k, v in ent.items() if k != x["e"]],
                  why(x), "From the record", rnd, x["id"])
    return None


def from_kev(D, rnd):
    kev = [k for k in D.get("kev", [])[:80] if k.get("v") and k.get("p")]
    vendors = list(dict.fromkeys(k["v"] for k in D.get("kev", []) if k.get("v")))
    if not kev or len(vendors) < 4:
        return None
    k = rnd.choice(kev)
    wrong = rnd.sample([v for v in vendors if v != k["v"]], 3)
    return _q(f"CISA lists {k['cve']} ({k['n']}) as exploited. Whose product is affected?", k["v"], wrong,
              f"{k['v']} {k['p']}, added to CISA's list on {k['a']}." + (f" Fix-by date for US agencies: {k['d']}." if k.get("d") else ""),
              "Exploited flaws", rnd, k.get("link") or None)


def from_claude(D, rnd, recent_qs):
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return None
    top = [f"- {x['t']}: {x['sum'][:220]}" for x in sorted(D["incidents"], key=lambda x: x["iso"], reverse=True)[:12]]
    prompt = ("Write ONE multiple-choice question for security staff at a bank, testing a concept (not a trivia date) "
              "that one of these recent stories illustrates. Exactly 4 options, one clearly correct, all plausible. "
              "Do not repeat these recent questions:\n" + "\n".join(recent_qs[-20:]) +
              "\n\nStories:\n" + "\n".join(top) +
              '\n\nReturn JSON only: {"q": "...", "right": "...", "wrong": ["...", "...", "..."], "why": "one or two sentences"}')
    txt = fetch.anthropic(prompt, "You write accurate, unambiguous security awareness questions. JSON only.",
                          os.environ.get("CLAUDE_MODEL") or "claude-haiku-5-5", 800)
    m = re.search(r"\{.*\}", txt or "", re.S)
    if not m:
        return None
    o = json.loads(m.group(0))
    if not (isinstance(o.get("q"), str) and isinstance(o.get("right"), str) and isinstance(o.get("wrong"), list) and len(o["wrong"]) >= 3):
        return None
    return _q(o["q"][:240], o["right"][:160], [str(w)[:160] for w in o["wrong"][:3]], str(o.get("why", ""))[:400], "Concept", rnd)


def from_bank(rnd, recent_qs):
    bank = json.load(open(BANK, encoding="utf-8"))
    fresh = [b for b in bank if b["q"] not in recent_qs] or bank
    b = rnd.choice(fresh)
    right = b["o"][b["a"]]
    return _q(b["q"], right, [o for o in b["o"] if o != right], b["why"], b["cat"], rnd)


def run(R):
    D, ts = R.D, R.ts
    cur = D.get("quiz")
    if cur and cur.get("d") == ts:
        return
    arch = D.setdefault("quizArchive", [])
    if cur and cur.get("d") and not any(a["d"] == cur["d"] for a in arch):
        arch.insert(0, cur)
    del arch[KEEP:]
    recent_qs = [q["q"] for a in arch for q in a["qs"]]
    rnd = random.Random(int(hashlib.sha1(ts.encode()).hexdigest()[:8], 16))
    qs = [from_record(D, rnd, ts), from_kev(D, rnd)]
    concept = None
    try:
        concept = from_claude(D, rnd, recent_qs)
    except Exception as e:
        R.failed.append({"n": "Claude quiz question", "err": str(e)[:160]})
    qs.append(concept or from_bank(rnd, recent_qs))
    qs = [q for q in qs if q]
    while len(qs) < 3:
        qs.append(from_bank(rnd, recent_qs + [q["q"] for q in qs]))
    D["quiz"] = {"d": ts, "qs": qs[:3]}
