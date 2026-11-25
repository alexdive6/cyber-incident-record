# Cyber Incident Record

A cyber threat dashboard that updates itself every night on GitHub, for free. It runs without your computer.

Every night at 02:00 New York time, GitHub runs `collector/run.py`. The script:
- reads 31 trusted sources: CISA's exploited-vulnerabilities list, ENISA, FIRST EPSS, NIST, government CERTs, SEC filings, Have I Been Pwned, ransomware.live and security newsrooms;
- merges what's new into `site/data/latest.json`;
- republishes the website.

On GitHub's free plan this setup costs nothing.

> **Good to know:** on GitHub's free plan, the repository and the website are **public**. Anyone with the link can open them. Everything on the page comes from public sources and is marked TLP:CLEAR. The page tells search engines not to list it. Never add internal or client information to this repository. If you need the site private later, see the last section.

---

## Set it up (about 15 minutes)

### 1. Create the repository
1. Sign in at https://github.com (create a free account if you don't have one).
2. Click **+** (top right), then **New repository**.
3. Name it `cyber-incident-record`, choose **Public**, then click **Create repository**.

### 2. Upload the files
1. Unzip `cyber-incident-record.zip` on your computer.
2. On the new repository page, click **uploading an existing file**.
3. Open the unzipped folder, select **everything inside it** and drag it onto the page. That means the `collector`, `site`, `tests` and `.github` folders and `README.md`.
4. Click **Commit changes**.

**Mac users:** Finder hides folders whose names start with a dot, including `.github`. Press **Cmd + Shift + .** in Finder to show it before you drag. Then check the upload added the file `.github/workflows/nightly.yml`.

If that file is missing, add it by hand:
1. Click **Add file**, then **Create new file**.
2. Type `.github/workflows/nightly.yml` as the name.
3. Paste in the contents of that file from the zip.
4. Click **Commit changes**.

### 3. Turn on the website
1. Go to **Settings**, then **Pages**.
2. Under **Build and deployment**, set **Source** to **GitHub Actions**.

### 4. Let the nightly job save its data
1. Go to **Settings**, then **Actions**, then **General**.
2. Under **Workflow permissions**, choose **Read and write permissions**, then click **Save**.

### 5. Add your email (recommended)
1. Go to **Settings**, then **Secrets and variables**, then **Actions**.
2. Open the **Variables** tab and click **New repository variable**.
3. Name it `CONTACT_EMAIL` and enter your email address. The SEC asks automated readers to identify themselves this way.

### 6. Optional keys (add them later if you like)
On the same screen, open the **Secrets** tab and click **New repository secret** for each key you want.

| Secret name | What it does | Where to get it |
|---|---|---|
| `NVD_API_KEY` | Faster severity (CVSS) lookups from NIST | Free: https://nvd.nist.gov/developers/request-an-api-key |
| `ANTHROPIC_API_KEY` | Claude writes each entry's title and summary in plain language, removes noise, and writes the monthly analyst's note. Small cost per night. | https://console.anthropic.com |

Without the Anthropic key the dashboard still works. It uses keyword rules instead, so the titles are the newsroom headlines and the ratings are rougher.

### 6b. Our patching (private inventory)
The **Our patching** tab lists every vendor fix for the platforms you run, with CVSS, EPSS, a priority and a CISA exploited check. The list of platforms and exact versions is private:

1. Copy `collector/inventory.example.json` to `collector/inventory.local.json` (git ignores it) and describe your platforms. Each one has a `source`: `msrc` (Windows), `redhat` (RHEL), `aix` (AIX/VIOS), `cisco` (Cisco advisories) or `nvd` (any product NIST describes, filtered by a version regex in `match`).
2. Add a repository secret named `PATCH_INVENTORY` and paste the whole file as its value.

Only each platform's display `name`, its `source` type and its `news` pattern are published. Versions, product filters and regexes stay in the secret. To change the inventory, edit the secret. Without it, the tab says it is not set up.

The **Daily quiz** needs no setup. With `ANTHROPIC_API_KEY`, Claude writes one of the three questions each night.

### 7. Run it for the first time
1. Open the **Actions** tab. If GitHub asks, click **I understand my workflows, go ahead and enable them**.
2. Click **Nightly update**, then **Run workflow**, then **Run workflow** again.
3. Wait about 5 minutes for a green tick.
4. Your site is at **https://YOUR-USERNAME.github.io/cyber-incident-record/**.

From then on it runs by itself every night.

**About the first run:** it loads CISA's full exploited list from 1 October. Flaws not already in the record are filed under their own dates, so they don't all appear as "New".

---

## Day to day

**The top bar** shows when the page was last updated. If any source failed overnight, it turns amber and names it. If most sources fail, GitHub marks the run red and emails you.

**Fixing an entry by hand:** edit `collector/overrides.json` on GitHub (open the file, click the pencil, then **Commit changes**). The site republishes in about a minute, and your change survives future runs.

```json
{
  "incidents": {
    "equinor": {"sev": "crit", "fix": "Contained on 20 Nov, per Equinor."}
  },
  "hide": ["some-entry-id"],
  "actNow": []
}
```

- `incidents`: change any field of an entry. To find an entry's id, open it on the site; it appears in `site/data/latest.json`.
- `hide`: remove entries from the page.
- `actNow`: pin the Act now cards yourself, for example `["puppet", "nginx2root"]`. Leave it empty `[]` to use the automatic rule: newest critical exploited flaws first, then critical fixes released in the last 4 days, then high.

**Adding or removing a source:** edit `collector/sources.json`. Each source has a `kind`:
- `rss` for news and government feeds;
- `kev`, `euvd`, `epss`, `nvd`, `sec`, `hibp` or `ransomware` for the APIs;
- `reference` for sources listed on the page but not read nightly.

---

## What the job does each night

1. **Exploited flaws:** CISA's catalog and ENISA's EU list. Each new flaw becomes an entry, with EPSS (the chance it gets exploited in the next 30 days) and CVSS scores.
2. **Feeds:** government advisories go to the Advisories list. News is filtered to real attacks and critical flaws; guides, webinars and funding news are dropped.
3. **Merging:** stories about the same victim or CVE become one entry with several sources. Follow-up stories update the existing entry and mark it Updated.
4. **Rating:**
   - Critical: money stolen, a bank, hospital or utility halted, 10 million+ records, or a CVSS 9+ exploited flaw.
   - High: a confirmed breach or any finance intrusion.
   - Notable: everything else.
   - Status: Confirmed (victim, regulator or government source), Reported (press or researchers) or Claim (ransomware leak site only).
5. **Patch now list:** critical CVEs with a fix out but no known exploitation, once two newsrooms or one official source report them. They leave after 21 days, or as soon as they show up as exploited.
6. **Saving:** the job updates `site/data/latest.json` and writes that night's changes to `site/data/archive/YYYY-MM/YYYY-MM-DD.json`. Entries older than 400 days move to `archive/older.json`.

---

## Things to know

- GitHub sometimes starts scheduled runs a few minutes late. That doesn't matter here.
- **GitHub pauses schedules on inactive public repositories.** It does this when nothing has happened in the repository for 60 days. The nightly data save should keep it active. If the Actions tab ever shows "This scheduled workflow is disabled", click **Enable workflow**.
- **If a step fails with a message about an action version** (for example `actions/checkout@v5`), raise the version number in `.github/workflows/nightly.yml`.
- **News sites change their feed addresses from time to time.** A source that keeps failing in the top bar usually needs its address updated in `sources.json`.

## Test it on your computer (optional)

This needs Python 3.10 or newer.

```bash
python tests/make_fixtures.py                              # sample data, no internet needed
CIR_FIXTURES=tests/fixtures python collector/run.py        # Windows PowerShell: $env:CIR_FIXTURES="tests/fixtures"; python collector/run.py
cd site && python -m http.server 8000                      # then open http://localhost:8000
```

Running `python collector/run.py` without `CIR_FIXTURES` reads the real sources.

The test run changes `site/data/latest.json`. Don't upload a test version of that file; use the one from the zip, or let the nightly job write it.

## Making it private later

To keep the site off the public internet:
1. Host it on **Cloudflare Pages**, which is free.
2. Put **Cloudflare Access** in front of it. Access is free for up to 50 people, and each colleague signs in with a one-time code sent to their work email.

The collector stays the same. Only the last steps of the workflow change, to publish to Cloudflare instead of GitHub Pages.
