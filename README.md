# jackalhunt

A time-boxed recon orchestrator in a single bash script. You give it a domain;
it enumerates subdomains from many sources at once, finds the live ones,
screenshots them, fingerprints the stack, brute-forces directories cleanly, and
crawls for URLs/params/JS/APIs — a full `run_all` finishes in **~15 minutes**.

It wraps best-in-class tools (subfinder, httpx, ffuf/feroxbuster, katana,
gowitness, …) and falls back gracefully when one is missing. **Only run it
against assets you own or are explicitly authorized to test.**

```bash
./jackalhunt.sh                                # interactive menu
./jackalhunt.sh -t example.com -m 1            # subdomains + live + screenshots
./jackalhunt.sh -t example.com -m all -y       # full chain, no prompts
./jackalhunt.sh -t a.com,b.com -m all -y -s    # several targets, auto-screenshots
./jackalhunt.sh -l scope.txt -m 1 -y           # every domain in a scope file
```

## Modes

| # | Mode | What you get |
|---|------|--------------|
| 1 | **Domain search** | `all_domains.txt`, `working_domains.txt`, auto-screenshots |
| 2 | **Fingerprint + dirs** | `tech.txt`, `valuable_targets.txt`, `dirs/`, `all_dirs.txt` |
| 3 | **Crawl** | `crawl_urls.txt`, `urls_with_params.txt`, `js_files.txt`, `api_endpoints.txt` |
| 4 | **Screenshots** | `screenshots/` + a browsable `gallery.html` |
| all | 1 → 2 → 3 | everything, in ~15 min |

Each target gets its own `~/recon/results/<target>_<timestamp>/` folder.

## Subdomain enumeration — no stone unturned

Mode 1 runs 15+ sources **concurrently** and merges them unique:

- **Tools:** subfinder (`-all`), assetfinder, findomain, amass (passive),
  github-subdomains (with `GITHUB_TOKEN`)
- **Key-free APIs:** crt.sh, certspotter, hackertarget, AlienVault OTX,
  rapiddns, urlscan.io, subdomain.center, Wayback CDX
- **Search-engine dorking:** `site:` dorks run across Google, Bing and
  DuckDuckGo. Raw HTML scraping is bot-blocked and best-effort, so for
  **reliable Google dorking set `GOOGLE_API_KEY` + `GOOGLE_CSE_ID`** (Custom
  Search JSON API, free 100 queries/day) — it's then used first and extensively.
  theHarvester adds more engines, and a `search_dorks.txt` of ready dorks is
  written for manual follow-up.
- **Shodan** DNS (with `SHODAN_API_KEY`)
- **Active (optional, on by default):** wildcard-filtered DNS brute force via
  `puredns`, and `alterx` permutations resolved live — both guarded so they
  never explode or blow the time budget.

Everything is resolved, then HTTP-probed with ProjectDiscovery `httpx`, so
`working_domains.txt` is genuinely live hosts, not just DNS records.

## Directory search — clean, not junk

ffuf runs with **`-ac` auto-calibration**: it learns each host's soft-404
baseline and drops anything that matches it, plus `-fc 404` and a status
allowlist. A host that returns the same response for every path yields **zero**
results instead of thousands of false hits. Output is clean, code-sorted
`STATUS  SIZE  URL`. Hosts are brute-forced **4 at a time in parallel**, ranked
so interesting tech / auth-gated / error hosts go first. Falls back to
feroxbuster then gobuster.

On top of brute force, mode 2 runs **Google-dork content discovery** on the top
hosts (`site:host inurl:admin`, `ext:php`, `intitle:index.of`, …). Anything a
search engine has indexed genuinely exists, so these are zero-junk real paths
that brute force alone would miss — merged into `all_dirs.txt` and
`dorked_dirs.txt`.

## Requirements

Core: `bash`, `curl`. Recommended tools (install what you can):

```
subfinder assetfinder findomain amass httpx(PD) dnsx puredns alterx
ffuf feroxbuster gobuster katana gau gowitness jq theHarvester
```

### macOS setup

The script is cross-platform but needs GNU coreutils on macOS for its time
budgets and progress meters:

```bash
brew install coreutils              # provides timeout/stdbuf/nproc
brew install --cask chromium        # headless browser for screenshots
# ProjectDiscovery httpx (a compiled binary, not the pip 'httpx'):
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

Chromium is an unsigned cask; if a first headless launch is blocked by
Gatekeeper, clear the quarantine once: `xattr -dr com.apple.quarantine
/Applications/Chromium.app`. The script auto-detects browsers installed as macOS
`.app` bundles (Chromium/Chrome/Brave/Edge), not just ones on `PATH`.

The script auto-detects the coreutils `gnubin` dir, prefers the compiled
(Mach-O/ELF) httpx over the Python one, and auto-discovers SecLists wordlists
across `/usr/share`, brew's `share`, and `./wordlists/`.

## Tuning (env vars)

| Var | Default | Effect |
|-----|---------|--------|
| `JACKAL_YES=1` | – | skip the authorization prompt |
| `JACKAL_AUTOSHOT=0` | `1` | don't auto-screenshot after mode 1 |
| `JACKAL_SUB_BRUTE=0` | `1` | skip DNS brute force |
| `JACKAL_PERMUTE=0` | `1` | skip alterx permutations |
| `JACKAL_HEADLESS=1` | – | render JS when crawling (mode 3) |
| `GITHUB_TOKEN` / `SHODAN_API_KEY` | – | enable those sources |
| `GOOGLE_API_KEY` + `GOOGLE_CSE_ID` | – | reliable Google dorking via Custom Search API |

Time budgets (seconds) live at the top of the script: `DOMAIN_ENUM_BUDGET`,
`SUB_BRUTE_BUDGET`, `DOMAIN_PROBE_BUDGET`, `DIR_BUDGET`, `CRAWL_BUDGET`,
`SHOT_BUDGET` — tuned so `run_all` stays within ~15 minutes.
