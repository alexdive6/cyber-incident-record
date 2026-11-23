"""Rating and classification rules.

Everything here is plain keyword logic so it runs with no API key.
If ANTHROPIC_API_KEY is set, run.py asks Claude to refine titles, summaries
and ratings afterwards; these rules are still the fallback.
"""
import re

# ---- Is a news item about an actual attack or exploited flaw? ----
ATTACK = re.compile(
    r"\b(breach(ed|es)?|hack(ed|ers?|ing)?|ransomware|cyber ?-?attacks?|data (leak|theft)|leak(ed|s)?|"
    r"stole|stolen|compromis\w*|extort\w*|intrusion|exploit(ed|ing|ation)|zero[- ]day|0-day|wiper|heist|"
    r"skimm\w+|ddos|backdoor\w*|malicious (update|package|code)|supply[- ]chain attack|"
    r"unauthori[sz]ed access|incident|threat actors?|espionage)\b", re.I)
NOT_INCIDENT = re.compile(
    r"\b(webinar|podcast|sponsored|how to|guide to|best practices|top \d+|review:|raises \$|funding round|"
    r"acquires|acquisition|appoints|hires|launches|partnership|conference|award|opinion|interview|"
    r"week in review|weekly recap|newsletter|explained)\b", re.I)
EXPLOITED = re.compile(r"\b(actively exploited|exploited in the wild|under (active )?attack|in-the-wild|zero[- ]day)\b", re.I)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
CONFIRM = re.compile(r"\b(confirm(s|ed)|disclos(es|ed)|says? (it|hackers)|notif(ies|ied)|statement|filing|8-K)\b", re.I)

SECTORS = [
    ("FIN", r"\b(bank(s|ing)?|credit union|insurer|insurance|payments?|fintech|brokerage|lender|lending|visa|mastercard|asset manager|stock exchange|financial)\b"),
    ("CRYPTO", r"\b(crypto\w*|bitcoin|ethereum|blockchain|stablecoin|defi|wallet|web3|nft)\b"),
    ("HEALTH", r"\b(hospital|health\w*|medical|clinic|pharma\w*|patients?|dental|nhs)\b"),
    ("GOV", r"\b(government|ministry|federal|municipal\w*|city of|county|state agency|agency|police|court|parliament|embassy|military|army|navy)\b"),
    ("EDU", r"\b(universit\w+|school|college|education\w*|students?)\b"),
    ("TEL", r"\b(telecom\w*|carrier|mobile operator|isp|broadband|broadcaster|newspaper|media group)\b"),
    ("LOG", r"\b(logistics|shipping|port|postal|freight|courier|airport)\b"),
    ("IND", r"\b(energy|oil|gas|utilit\w+|power grid|electric\w*|water|manufactur\w*|factory|plant|defen[cs]e|drone|aerospace|automotive|chemical|mining)\b"),
    ("RETAIL", r"\b(retail\w*|store|supermarket|grocer\w*|hotel|travel|airline|restaurant|e-?commerce|fashion|brand|consumer|gaming)\b"),
    ("TECH", r"\b(software|saas|cloud|vendor|developer|github|npm|pypi|open[- ]source|ai |chip|semiconductor|it provider|msp|data center)\b"),
]

REGIONS = {
    "AMER": r"\b(u\.?s\.?|usa|united states|american|canada|canadian|brazil\w*|mexic\w+|argentin\w+|chile\w*|colombia\w*|peru\w*|new york|california|texas|florida)\b",
    "EMEA": r"\b(uk|u\.k\.|britain|british|england|scotland|ireland|irish|france|french|germany|german|italy|italian|spain|spanish|portugal|netherlands|dutch|belgi\w+|switzerland|swiss|austria\w*|poland|polish|sweden|swedish|norway|norwegian|denmark|danish|finland|finnish|estonia\w*|latvia\w*|lithuania\w*|ukrain\w+|russia\w*|europe\w*|eu\b|israel\w*|iran\w*|saudi|emirat\w+|uae|qatar\w*|turk\w+|egypt\w*|africa\w*|nigeria\w*|kenya\w*|morocc\w+)\b",
    "APAC": r"\b(japan\w*|china|chinese|korea\w*|taiwan\w*|india\w*|australia\w*|new zealand|singapore\w*|malaysia\w*|indonesia\w*|thai\w*|vietnam\w*|philippin\w+|hong kong|pakistan\w*|bangladesh\w*|asia\w*)\b",
}
COUNTRY_NAMES = ["United States", "US", "Canada", "Brazil", "Mexico", "UK", "France", "Germany", "Italy", "Spain",
                 "Netherlands", "Switzerland", "Austria", "Poland", "Sweden", "Norway", "Denmark", "Finland", "Ukraine",
                 "Russia", "Israel", "Iran", "Japan", "China", "South Korea", "Taiwan", "India", "Australia",
                 "Singapore", "Malaysia", "Indonesia", "Thailand", "Vietnam", "Philippines", "Hong Kong"]

ENTRY = [
    ("social", r"\b(phish\w*|social engineering|vish\w*|impersonat\w+|deepfake|fake (job|interview|recruiter)|sim[- ]swap|help ?desk)\b"),
    ("third", r"\b(third[- ]party|vendor|supplier|service provider|supply[- ]chain|contractor|via [A-Z]\w+)\b"),
    ("cred", r"\b(stolen credentials?|credential\w*|password\w*|tokens?|api keys?|secrets?|session cookies?|infostealer)\b"),
    ("flaw", r"\b(vulnerabilit\w+|exploit\w*|zero[- ]day|CVE-\d{4}-\d+|unpatched|flaw)\b"),
    ("other", r"\b(misconfigur\w+|exposed database|left (open|exposed)|unsecured|publicly accessible)\b"),
]

TAGS = [
    ("ransom", r"\b(ransomware|extortion|leak site|encrypt\w+)\b"),
    ("state", r"\b(state[- ]sponsored|nation[- ]state|apt\d*|north korea\w*|lazarus|china[- ]linked|chinese hackers|russian hackers|russia[- ]linked|iran\w*[- ]linked|espionage)\b"),
    ("ai", r"\b(ai agents?|agentic|artex|llm|autonomous ai|ai-powered|deepfake)\b"),
    ("mail", r"\b(outlook|exchange server|email gateway|email security|phishing emails?|business email compromise|bec)\b"),
]

MONEY = re.compile(r"[$€£]\s?(\d+(?:[.,]\d+)?)\s?(m|mn|million|bn|billion)\b", re.I)
RECORDS = re.compile(r"(\d+(?:[.,]\d+)?)\s?(million|m)\s+(customers|people|users|records|patients|accounts|members|individuals)", re.I)


def first_match(pairs, text, default):
    for key, rx in pairs:
        if re.search(rx, text, re.I):
            return key
    return default


def sector(text):
    return first_match(SECTORS, text, "X")


def region(text):
    hits = [k for k, rx in REGIONS.items() if re.search(rx, text, re.I)]
    return hits[0] if len(hits) == 1 else "GLOBAL"


DEMONYMS = {"American": "US", "Canadian": "Canada", "British": "UK", "French": "France", "German": "Germany", "Italian": "Italy",
            "Spanish": "Spain", "Dutch": "Netherlands", "Swiss": "Switzerland", "Swedish": "Sweden", "Norwegian": "Norway",
            "Danish": "Denmark", "Finnish": "Finland", "Polish": "Poland", "Irish": "Ireland", "Japanese": "Japan",
            "Korean": "South Korea", "South Korean": "South Korea", "Chinese": "China", "Taiwanese": "Taiwan", "Indian": "India",
            "Australian": "Australia", "Singaporean": "Singapore", "Indonesian": "Indonesia", "Brazilian": "Brazil",
            "Israeli": "Israel", "Ukrainian": "Ukraine", "Russian": "Russia"}


def where(text):
    for d, c in DEMONYMS.items():
        if re.search(r"\b" + d + r"\b", text):
            return c
    for c in COUNTRY_NAMES:
        if re.search(r"\b" + re.escape(c) + r"\b", text):
            return "US" if c == "United States" else c
    return "Global"


def entry_method(text):
    return first_match(ENTRY, text, "undisc")


def tags_for(text, sec, entry):
    t = [k for k, rx in TAGS if re.search(rx, text, re.I)]
    if entry == "social":
        t.append("human")
    if entry == "third":
        t.append("vendor")
    if sec in ("FIN", "CRYPTO"):
        t.append("finance")
    return sorted(set(t))


def money_m(text):
    best = 0.0
    for n, unit in MONEY.findall(text):
        v = float(n.replace(",", "."))
        best = max(best, v * 1000 if unit.lower().startswith("b") else v)
    return best


def records_m(text):
    best = 0.0
    for n, _u, _w in RECORDS.findall(text):
        best = max(best, float(n.replace(",", ".")))
    return best


def severity_incident(text, sec, conf):
    """crit / high / med for an attack story."""
    if conf == "claim":
        return "med"
    stolen = money_m(text) if re.search(r"\b(stole|stolen|theft|heist|drained|wired)\b", text, re.I) else 0
    if stolen >= 10 or records_m(text) >= 10:
        return "crit"
    if re.search(r"\b(halt\w*|shut ?down|divert\w*|offline|outage|disrupt\w*)\b", text, re.I) and sec in ("FIN", "HEALTH", "IND", "GOV"):
        return "crit"
    if sec in ("FIN", "CRYPTO") or re.search(r"\b(ransomware|breach\w*|stolen|exfiltrat\w+|leaked)\b", text, re.I):
        return "high"
    return "med"


def severity_flaw(cvss):
    if cvss is None:
        return "high"
    if cvss >= 9:
        return "crit"
    if cvss >= 7:
        return "high"
    return "med"


STOP = set("""a an the and or of for to in on at by with from as is are was were be been it its this that these those
new over after amid into via says say said report reports reported warns warning hit hits hackers hacker attack attacks
cyberattack breach data million says firm company group""".split())


def tokens(title):
    return {w for w in re.findall(r"[a-z0-9][a-z0-9\-]{2,}", title.lower()) if w not in STOP}


def jaccard(a, b):
    return len(a & b) / len(a | b) if a and b else 0.0


GENERIC_NAMES = set("""Microsoft Google Apple Amazon Cisco Linux Windows Chrome Android iOS CISA FBI NSA The US UK EU
Europe China Russia Iran North Korea South New Critical Hackers Ransomware Researchers Security Cyber Data Zero""".split())


# ---- What was hit: the company, and the software that was exploited ----
# Ordered most specific first; the first few matches are kept.
SOFTWARE = [
    ("Cisco ASA / FTD", r"\bcisco (asa|adaptive security|firepower|ftd|secure firewall)\b"),
    ("Cisco IOS XE", r"\bios ?xe\b"),
    ("Cisco ISE", r"\bcisco ise\b|identity services engine"),
    ("Fortinet FortiGate / FortiOS", r"\bforti(gate|os)\b"),
    ("Fortinet FortiWeb", r"\bfortiweb\b"),
    ("Fortinet FortiManager", r"\bfortimanager\b"),
    ("Ivanti Connect Secure", r"\bivanti connect secure\b|\bpulse secure\b"),
    ("Ivanti EPMM", r"\bivanti (epmm|endpoint manager mobile)\b"),
    ("Palo Alto PAN-OS / GlobalProtect", r"\bpan-?os\b|\bglobalprotect\b"),
    ("Citrix NetScaler", r"\bnetscaler\b|\bcitrix (adc|gateway)\b"),
    ("SonicWall", r"\bsonicwall\b"),
    ("Check Point", r"\bcheck point\b"),
    ("VMware ESXi", r"\besxi?\b"),
    ("VMware vCenter", r"\bvcenter\b"),
    ("Microsoft Exchange Server", r"\bexchange server\b|\boutlook web access\b|\bowa\b"),
    ("Microsoft SharePoint", r"\bsharepoint\b"),
    ("Microsoft 365 / Entra ID", r"\b(microsoft|office) 365\b|\bentra id\b|\bazure ad\b"),
    ("Microsoft Outlook", r"\boutlook\b"),
    ("Windows", r"\bwindows\b"),
    ("Google Chrome", r"\bchrome\b|\bchromium\b"),
    ("Apple iOS / macOS", r"\b(ios|ipados|macos|webkit)\b"),
    ("Android", r"\bandroid\b"),
    ("Linux kernel", r"\blinux kernel\b"),
    ("ConnectWise ScreenConnect", r"\bscreenconnect\b"),
    ("SimpleHelp", r"\bsimplehelp\b"),
    ("N-able N-central", r"\bn-central\b"),
    ("Kaseya VSA", r"\bkaseya\b"),
    ("SAP NetWeaver", r"\bnetweaver\b"),
    ("Oracle E-Business Suite", r"\boracle e-?business suite\b|\boracle ebs\b"),
    ("Oracle WebLogic", r"\bweblogic\b"),
    ("Salesforce", r"\bsalesforce\b"),
    ("Snowflake", r"\bsnowflake\b"),
    ("Okta", r"\bokta\b"),
    ("MOVEit Transfer", r"\bmoveit\b"),
    ("GoAnywhere MFT", r"\bgoanywhere\b"),
    ("Cleo file transfer", r"\bcleo (harmony|vltrader|lexicom)\b"),
    ("Atlassian Confluence", r"\bconfluence\b"),
    ("Atlassian Jira", r"\bjira\b"),
    ("GitLab", r"\bgitlab\b"),
    ("GitHub Actions", r"\bgithub actions\b|\bgithub workflows?\b"),
    ("npm package", r"\bnpm\b"),
    ("PyPI package", r"\bpypi\b"),
    ("WordPress plugin", r"\bwordpress plugin\b"),
    ("WordPress", r"\bwordpress\b"),
    ("Apache Tomcat", r"\btomcat\b"),
    ("Apache Struts", r"\bstruts\b"),
    ("Log4j", r"\blog4j\b|\blog4shell\b"),
    ("PHP", r"\bphp\b"),
    ("Jenkins", r"\bjenkins\b"),
    ("Veeam Backup", r"\bveeam\b"),
    ("Zimbra", r"\bzimbra\b"),
    ("Roundcube", r"\broundcube\b"),
    ("Barracuda ESG", r"\bbarracuda\b"),
    ("Zyxel", r"\bzyxel\b"),
    ("D-Link", r"\bd-link\b"),
    ("TP-Link", r"\btp-link\b"),
    ("Juniper", r"\bjuniper\b|\bjunos\b"),
    ("F5 BIG-IP", r"\bbig-?ip\b"),
    ("BeyondTrust", r"\bbeyondtrust\b"),
    ("SolarWinds", r"\bsolarwinds\b"),
    ("Synology", r"\bsynology\b"),
    ("QNAP", r"\bqnap\b"),
    ("Commvault", r"\bcommvault\b"),
    ("CrushFTP", r"\bcrushftp\b"),
    ("Zoho ManageEngine", r"\bmanageengine\b"),
]

COMPANY_VERB = re.compile(
    r"^([A-Z][\w.&'’-]*(?:\s+[A-Z0-9&][\w.&'’-]*){0,4})\s+"
    r"(?:confirms|discloses|says|reports|warns|notifies|suffers|hit by|struck by|hacked|breached|investigat\w+|"
    r"probes|admits|data breach|cyberattack|cyber attack|ransomware attack|security incident|outage)\b")


def software(text):
    """The software or product named as exploited or abused, or ''."""
    hits = []
    for label, rx in SOFTWARE:
        if re.search(rx, text, re.I) and not any(label in h or h in label for h in hits):
            hits.append(label)
        if len(hits) == 3:
            break
    return ", ".join(hits)


_NAME = r"([A-Z][\w.&'’-]*(?:\s+[A-Z0-9&][\w.&'’-]*){0,3})"
COMPANY_OBJ = re.compile(r"\b(?:breach(?:es|ed)?|hack(?:s|ed)?|hits?|attacks?|targets?|extorts?)\s+" + _NAME +
                         r"|\b(?:stole|steal|steals|stolen|drained?|exfiltrated)\b.*?\b(?:from|at)\s+" + _NAME)


def company(title):
    """Best guess at the victim from a headline ('Acme confirms data breach', 'Hackers steal $5m from Acme'); '' if unsure."""
    title = title.strip()
    m = COMPANY_VERB.match(title)
    m2 = None if m else COMPANY_OBJ.search(title)
    name = (m.group(1) if m else (m2.group(1) or m2.group(2)) if m2 else "").strip()
    if not name or name in GENERIC_NAMES or name.split()[0] in GENERIC_NAMES:
        return ""
    return name


def names(title):
    """Capitalised words that likely name the victim (used for merging)."""
    return {w for w in re.findall(r"\b[A-Z][A-Za-z0-9&\-]{2,}\b", title) if w not in GENERIC_NAMES}
