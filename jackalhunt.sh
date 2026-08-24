#!/usr/bin/env bash
#
#      _            _         _ _                 _
#     (_) __ _  ___| | ____ _| | |__  _   _ _ __ | |_
#     | |/ _` |/ __| |/ / _` | | '_ \| | | | '_ \| __|
#     | | (_| | (__|   < (_| | | | | | |_| | | | | |_
#    _/ |\__,_|\___|_|\_\__,_|_|_| |_|\__,_|_| |_|\__|
#   |__/         jackalhunt — time-boxed recon orchestrator
#
#   Mode 1: Domain search      (hard cap ~5 min)  -> all_domains.txt + working_domains.txt
#   Mode 2: Fingerprint + dirs (hard cap ~10 min) -> tech.txt, then dir brute on valuable hosts
#   Mode 3: Crazier crawl      (katana / gau)     -> crawled urls, params, js, endpoints
#
#   Wraps subfinder, httpx, whatweb, ffuf/feroxbuster, katana and falls back
#   gracefully when a tool is missing. Use ONLY against assets you are
#   authorized to test.
#
set -uo pipefail

# ----------------------------------------------------------------------------- config
# output goes to ./output in the current folder by default (override with JACKAL_HOME)
BASE_DIR="${JACKAL_HOME:-$PWD}"
RESULTS_DIR="$BASE_DIR/output"
PATH="$HOME/go/bin:$PATH"     # PREPEND go tools so PD httpx beats /bin/httpx (python)
# macOS ships without GNU timeout/stdbuf/nproc; `brew install coreutils` provides
# them under a gnubin dir by their normal names. Prepend it so they resolve
# directly AND compose (e.g. `timeout ... stdbuf ...`) — a shell-function shim
# can't do that, since timeout execs its args and never sees a bash function.
for _gnubin in /opt/homebrew/opt/coreutils/libexec/gnubin /usr/local/opt/coreutils/libexec/gnubin; do
  [ -d "$_gnubin" ] && PATH="$_gnubin:$PATH"
done
export PATH

# time budgets (seconds) — tuned so a full `run_all` stays within ~15 minutes
DOMAIN_ENUM_BUDGET=120        # mode 1: passive+dork enumeration (all sources parallel)
SUB_BRUTE_BUDGET=75           # mode 1: DNS brute + permutation resolve
DOMAIN_PROBE_BUDGET=75        # mode 1: live HTTP probing
DIR_BUDGET=300                # mode 2: directory brute total (hosts run in parallel)
CRAWL_BUDGET=120              # mode 3: TOTAL budget (katana + gau share this)
SHOT_BUDGET=150               # mode 4: screenshotting (per invocation)
SHOT_CAP=80                   # max URLs to screenshot in one run

# behaviour toggles (env-overridable)
SUB_BRUTE="${JACKAL_SUB_BRUTE:-1}"    # DNS-bruteforce subdomains with a wordlist
SUB_PERMUTE="${JACKAL_PERMUTE:-1}"    # permute discovered names (alterx) and resolve
AUTO_SHOTS_MODE1="${JACKAL_AUTOSHOT:-1}"  # auto-screenshot working domains after mode 1

# wordlists — probe common SecLists locations (Linux, brew/macOS, kali, repo-local)
# and fall back gracefully. Filled in by _resolve_wordlists() at startup.
WL_DIR_BIG=""; WL_DIR_SMALL=""; WL_SUB=""
_SL_DIRS="/usr/share/seclists /opt/homebrew/share/seclists /usr/local/share/seclists $HOME/seclists $HOME/.seclists"
_resolve_wordlists(){
  local d
  for d in $_SL_DIRS; do
    [ -z "$WL_DIR_BIG" ]   && [ -f "$d/Discovery/Web-Content/raft-large-directories.txt" ] && WL_DIR_BIG="$d/Discovery/Web-Content/raft-large-directories.txt"
    [ -z "$WL_DIR_SMALL" ] && [ -f "$d/Discovery/Web-Content/common.txt" ] && WL_DIR_SMALL="$d/Discovery/Web-Content/common.txt"
    [ -z "$WL_SUB" ] && [ -f "$d/Discovery/DNS/subdomains-top1million-110000.txt" ] && WL_SUB="$d/Discovery/DNS/subdomains-top1million-110000.txt"
    [ -z "$WL_SUB" ] && [ -f "$d/Discovery/DNS/subdomains-top1million-5000.txt" ] && WL_SUB="$d/Discovery/DNS/subdomains-top1million-5000.txt"
  done
  # repo-local fallbacks bundled alongside this script (./wordlists/*)
  local self; self="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
  [ -z "$WL_DIR_BIG" ]   && [ -f "$self/wordlists/content-common.txt" ] && WL_DIR_BIG="$self/wordlists/content-common.txt"
  [ -z "$WL_DIR_SMALL" ] && [ -f "$self/wordlists/content-common.txt" ] && WL_DIR_SMALL="$self/wordlists/content-common.txt"
  [ -z "$WL_SUB" ]       && [ -f "$self/wordlists/subdomains-common.txt" ] && WL_SUB="$self/wordlists/subdomains-common.txt"
  : "${WL_DIR_BIG:=/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt}"
  : "${WL_DIR_SMALL:=/usr/share/seclists/Discovery/Web-Content/common.txt}"
}

THREADS="$(( $(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4) * 8 ))"

# ----------------------------------------------------------------------------- colors
if [ -t 1 ]; then
  R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[34m'; C=$'\e[36m'; W=$'\e[1m'; N=$'\e[0m'
else
  R=''; G=''; Y=''; B=''; C=''; W=''; N=''
fi
info(){ printf "%s[*]%s %s\n" "$C" "$N" "$*"; }
ok(){   printf "%s[+]%s %s\n" "$G" "$N" "$*"; }
warn(){ printf "%s[!]%s %s\n" "$Y" "$N" "$*"; }
err(){  printf "%s[-]%s %s\n" "$R" "$N" "$*" >&2; }
have(){ command -v "$1" >/dev/null 2>&1; }

# run a long command with a live heartbeat so it NEVER looks frozen.
#   run_timed "<label>" <budget_seconds> <output_file> <command...>
# the command's stdout is streamed (line-buffered) into <output_file>; every few
# seconds we reprint elapsed time + how many result lines have landed so far.
run_timed(){
  local label="$1" budget="$2" outfile="$3"; shift 3
  : > "$outfile"
  ( timeout "$budget" stdbuf -oL "$@" > "$outfile" 2>/dev/null ) &
  local pid=$! s=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r%s[*]%s %s  %ds elapsed · %s lines%s" \
      "$C" "$N" "$label" "$s" "$(wc -l < "$outfile" 2>/dev/null || echo 0)" "$(printf '\033[K')"
    sleep 3; s=$((s+3))
  done
  wait "$pid" 2>/dev/null
  printf "\r%s" "$(printf '\033[K')"
}

banner(){
cat <<EOF
${C}${W}
      _            _         _ _                 _
     (_) __ _  ___| | ____ _| | |__  _   _ _ __ | |_
     | |/ _\` |/ __| |/ / _\` | | '_ \\| | | | '_ \\| __|
     | | (_| | (__|   < (_| | | | | | |_| | | | | |_
    _/ |\\__,_|\\___|_|\\_\\__,_|_|_| |_|\\__,_|_| |_|\\__|
   |__/       ${N}${C}jackalhunt · subfinder httpx ffuf katana${N}
EOF
}

# --- resolve the REAL ProjectDiscovery httpx (an ELF binary), not python httpx ----
HTTPX=""
resolve_httpx(){
  local c
  for c in "$HOME/go/bin/httpx" $(command -v -a httpx 2>/dev/null); do
    [ -x "$c" ] || continue
    # PD httpx is a compiled binary: ELF on Linux, Mach-O on macOS. Python httpx
    # is a text script, so matching either binary format rules the python one out.
    if file -b "$c" 2>/dev/null | grep -qiE 'ELF|Mach-O'; then HTTPX="$c"; return 0; fi
  done
  HTTPX=""      # only python httpx (or none) available -> callers fall back
  return 1
}

# ----------------------------------------------------------------------------- helpers
OUT=""   # per-run output dir, set by set_target()

set_target(){
  TARGET="$1"
  TARGET="${TARGET#http://}"; TARGET="${TARGET#https://}"; TARGET="${TARGET%%/*}"
  [ -z "$TARGET" ] && { err "empty target"; return 1; }
  OUT="$RESULTS_DIR/${TARGET}_$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$OUT"
  ok "target: ${W}$TARGET${N}"
  ok "output: $OUT"
}

authz_gate(){
  [ "${JACKAL_YES:-0}" = "1" ] && return 0
  warn "Only scan assets you own or are explicitly authorized to test."
  read -r -p "$(printf '%s[?]%s Confirm you are authorized for %s? [y/N] ' "$Y" "$N" "$TARGET")" a
  case "$a" in y|Y|yes) return 0;; *) err "aborted"; return 1;; esac
}

# --- helpers for mode 1 -------------------------------------------------------
_gen_resolvers(){
  cat > "$OUT/.resolvers" <<'EOF'
1.1.1.1
1.0.0.1
8.8.8.8
8.8.4.4
9.9.9.9
149.112.112.112
208.67.222.222
208.67.220.220
64.6.64.6
77.88.8.8
EOF
}

# ready-to-run dorks for manual deep digging (kept as a deliverable even though we
# also auto-run them across Google/Bing/DuckDuckGo below)
_gen_dorks(){
  local t="$TARGET"
  cat > "$OUT/search_dorks.txt" <<EOF
# Dorks for $t — also auto-run across Google/Bing/DuckDuckGo by jackalhunt.
# SUBDOMAINS
site:*.$t -www.$t
site:$t
# CONTENT / DIRECTORIES / FILES
site:$t (inurl:admin | inurl:login | inurl:dashboard | inurl:portal)
site:$t (ext:php | ext:asp | ext:aspx | ext:jsp | ext:do | ext:action)
site:$t (inurl:api | inurl:v1 | inurl:v2 | inurl:graphql | inurl:swagger | inurl:rest)
site:$t intitle:"index of"
site:$t (ext:sql | ext:log | ext:bak | ext:old | ext:env | ext:conf | ext:yml | ext:json | ext:xml)
site:$t (inurl:wp-content | inurl:wp-admin | inurl:phpmyadmin)
site:$t (inurl:config | inurl:setup | inurl:backup | inurl:test | inurl:dev | inurl:staging)
site:$t (inurl:? & (inurl:id | inurl:file | inurl:page | inurl:redirect | inurl:url))
# EXPOSURE / LEAKS
site:pastebin.com $t
site:github.com $t
site:gitlab.com $t
site:trello.com $t
site:s3.amazonaws.com $t
EOF
}

# --- automated search-engine dorking ------------------------------------------
# Reality check: scraping Google/Bing/DuckDuckGo HTML is bot-blocked and usually
# returns little. The RELIABLE programmatic Google-dork path is the Custom Search
# JSON API — set GOOGLE_API_KEY + GOOGLE_CSE_ID (free 100 queries/day) and it is
# used first, extensively. HTML scraping stays on as best-effort backup.
_UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
GCSE_KEY="${GOOGLE_API_KEY:-}"; GCSE_CX="${GOOGLE_CSE_ID:-}"
_urldecode(){ python3 -c 'import sys,urllib.parse as u; sys.stdout.write(u.unquote(sys.stdin.read()))' 2>/dev/null; }
_urlencode(){ python3 -c 'import sys,urllib.parse as u; sys.stdout.write(u.quote(sys.stdin.read()))' 2>/dev/null \
              || printf '%s' "$1" | sed 's/ /+/g; s/:/%3A/g; s/"/%22/g'; }
_dork_engines(){ [ -n "$GCSE_KEY" ] && [ -n "$GCSE_CX" ] && printf 'gcse '; printf 'google bing ddg'; }

# fetch one page of results for a query from one engine (page is 0-based).
# gcse returns JSON (result links); the rest return raw HTML — callers just grep.
_dork_fetch(){
  local engine="$1" q="$2" page="${3:-0}" enc
  enc="$(printf '%s' "$q" | _urlencode)"
  case "$engine" in
    gcse)   [ -n "$GCSE_KEY" ] && [ -n "$GCSE_CX" ] && \
              timeout 15 curl -s "https://www.googleapis.com/customsearch/v1?key=$GCSE_KEY&cx=$GCSE_CX&q=$enc&num=10&start=$((page*10+1))" 2>/dev/null ;;
    google) timeout 15 curl -s -A "$_UA" -H 'Accept-Language: en-US,en;q=0.9' \
              --cookie 'CONSENT=YES+' "https://www.google.com/search?q=$enc&num=100&start=$((page*10))" 2>/dev/null ;;
    bing)   timeout 15 curl -s -A "$_UA" "https://www.bing.com/search?q=$enc&count=30&first=$((page*10+1))" 2>/dev/null ;;
    ddg)    timeout 15 curl -s -A "$_UA" --data-urlencode "q=$q" "https://html.duckduckgo.com/html/" 2>/dev/null ;;
  esac
}

# harvest subdomains via site: dorks across every available engine
_dork_subs(){
  local t="$1" esc="$2" eng q p engines; engines="$(_dork_engines)"
  {
    for q in "site:*.$t -www.$t" "site:$t"; do
      for eng in $engines; do
        for p in 0 1 2; do _dork_fetch "$eng" "$q" "$p"; sleep 1; done
      done
    done
  } | _urldecode | grep -oE "[a-zA-Z0-9._-]+\.$esc" 2>/dev/null
}

# harvest INDEXED real paths/files for one host via content dorks. Anything a
# search engine has indexed genuinely exists -> zero-junk directory intel.
_dork_dirs(){
  local host="$1" esc eng q engines; engines="$(_dork_engines)"
  esc="$(printf '%s' "$host" | sed 's/\./\\./g')"
  {
    for q in \
      "site:$host inurl:admin" "site:$host inurl:login" "site:$host inurl:api" \
      "site:$host ext:php" "site:$host ext:aspx" "site:$host ext:jsp" \
      "site:$host ext:json OR ext:xml OR ext:conf OR ext:bak OR ext:old OR ext:env" \
      "site:$host intitle:index.of" "site:$host"; do
      for eng in $engines; do _dork_fetch "$eng" "$q" 0; sleep 1; done
    done
  } | _urldecode | grep -oE "https?://$esc(:[0-9]+)?/[^ \"'<>)]+" 2>/dev/null \
    | sed 's/&amp;.*//; s/[),.]*$//' | sort -u
}

# =============================================================================
# MODE 1 — DOMAIN SEARCH: many parallel sources + dorking + brute + permute
# =============================================================================
mode_domains(){
  local all="$OUT/all_domains.txt" live="$OUT/working_domains.txt"
  local SRC="$OUT/.src"; mkdir -p "$SRC"
  local esc; esc="$(printf '%s' "$TARGET" | sed 's/\./\\./g')"
  local hostre="[a-zA-Z0-9._-]+\.$esc"
  _gen_resolvers; _gen_dorks
  info "enumerating ${W}$TARGET${N} — 15+ sources in parallel (budget ${DOMAIN_ENUM_BUDGET}s)"

  local B="$DOMAIN_ENUM_BUDGET"
  # ---- passive tool sources (each self-times-out, all concurrent) ----
  ( have subfinder   && timeout "$B" subfinder -silent -all -d "$TARGET" 2>/dev/null ) > "$SRC/subfinder" &
  ( have assetfinder && timeout "$B" assetfinder --subs-only "$TARGET" 2>/dev/null ) > "$SRC/assetfinder" &
  ( have findomain   && timeout "$B" findomain -q -t "$TARGET" 2>/dev/null ) > "$SRC/findomain" &
  ( have amass       && timeout "$B" amass enum -passive -nocolor -silent -d "$TARGET" 2>/dev/null | awk '{print $1}' ) > "$SRC/amass" &
  local ght="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
  ( [ -n "$ght" ] && have github-subdomains && timeout "$B" github-subdomains -d "$TARGET" -t "$ght" -q 2>/dev/null ) > "$SRC/github" &

  # ---- key-free HTTP data sources ----
  ( timeout 60 curl -s "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null \
      | grep -oE '"common_name":"[^"]+"|"name_value":"[^"]+"' | sed -E 's/.*":"//; s/"$//; s/\\n/\n/g; s/^\*\.//' ) > "$SRC/crtsh" &
  ( timeout 60 curl -s "https://api.certspotter.com/v1/issuances?domain=$TARGET&include_subdomains=true&expand=dns_names" 2>/dev/null \
      | grep -oE "$hostre" ) > "$SRC/certspotter" &
  ( timeout 45 curl -s "https://api.hackertarget.com/hostsearch/?q=$TARGET" 2>/dev/null | cut -d, -f1 ) > "$SRC/hackertarget" &
  ( timeout 45 curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$TARGET/passive_dns" 2>/dev/null \
      | grep -oE '"hostname": *"[^"]+"' | sed -E 's/.*": *"//; s/"$//' ) > "$SRC/otx" &
  ( timeout 45 curl -s "https://rapiddns.io/subdomain/$TARGET?full=1" 2>/dev/null | grep -oE "$hostre" ) > "$SRC/rapiddns" &
  ( timeout 45 curl -s "https://urlscan.io/api/v1/search/?q=domain:$TARGET&size=10000" 2>/dev/null | grep -oE "$hostre" ) > "$SRC/urlscan" &
  ( timeout 45 curl -s "https://api.subdomain.center/?domain=$TARGET" 2>/dev/null | grep -oE "$hostre" ) > "$SRC/subdomaincenter" &
  ( timeout 90 curl -s "http://web.archive.org/cdx/search/cdx?url=$TARGET&matchType=domain&fl=original&collapse=urlkey&output=text" 2>/dev/null \
      | grep -oE 'https?://[^/]+' | sed -E 's#https?://##; s#:[0-9]+$##' ) > "$SRC/wayback" &

  # ---- search-engine dorking: Google(CSE) + Bing + DuckDuckGo + theHarvester ----
  if [ -n "$GCSE_KEY" ] && [ -n "$GCSE_CX" ]; then
    info "Google dorking via Custom Search API (reliable)"
  else
    warn "Google dorking limited: set GOOGLE_API_KEY + GOOGLE_CSE_ID for reliable results (scraping is best-effort)"
  fi
  ( _dork_subs "$TARGET" "$esc" ) > "$SRC/search_dorks" &
  ( have theHarvester && { timeout 120 theHarvester -d "$TARGET" -b certspotter,crtsh,duckduckgo,otx,rapiddns,urlscan,hackertarget -f "$OUT/.th" >/dev/null 2>&1; \
       grep -hoE "$hostre" "$OUT/.th.json" "$OUT/.th.xml" 2>/dev/null; } ) > "$SRC/theharvester" &

  # ---- Shodan (optional key) ----
  local skey="${SHODAN_API_KEY:-$(cat "$HOME/.config/shodan/api_key" 2>/dev/null)}"
  ( [ -n "$skey" ] && timeout 60 curl -s "https://api.shodan.io/dns/domain/$TARGET?key=$skey" 2>/dev/null \
      | grep -oE '"subdomains":\[[^]]*\]' | grep -oE '"[^"]+"' | tr -d '"' | grep -v '^subdomains$' | sed "s/\$/.$TARGET/" ) > "$SRC/shodan" &
  [ -z "$skey" ] && warn "Shodan skipped (set SHODAN_API_KEY to enable)"

  # heartbeat until all background sources finish (or their own timeouts fire)
  local s=0
  while [ -n "$(jobs -rp)" ]; do
    printf "\r%s[*]%s enumerating  %ds · %s unique so far%s" "$C" "$N" "$s" \
      "$(cat "$SRC"/* 2>/dev/null | grep -oE "$hostre" | sort -u | wc -l | tr -d ' ')" "$(printf '\033[K')"
    sleep 3; s=$((s+3)); [ "$s" -gt $((B+140)) ] && break
  done
  wait 2>/dev/null
  printf "\r%s" "$(printf '\033[K')"

  # Extract maximal host tokens, then keep only those whose suffix is EXACTLY the
  # target — so "example.company" can't masquerade as a subdomain of example.com.
  { cat "$SRC"/* 2>/dev/null | tr '[:upper:]' '[:lower:]' \
      | grep -oE '[a-z0-9._-]+' | grep -E "(^|\.)$esc\$"; printf '%s\n' "$TARGET"; } \
    | sed 's/^\*\.//; s/^\.*//; s/\.$//' | grep -E "\.$esc\$|^$esc\$" | sort -u > "$all"
  rm -rf "$SRC"; rm -f "$OUT/.th" "$OUT/.th.json" "$OUT/.th.xml"
  ok "$(wc -l < "$all" | tr -d ' ') unique subdomains from passive + dork sources"

  # ---- active DNS brute force (wildcard-filtered via puredns) ----
  if [ "$SUB_BRUTE" = "1" ] && [ -n "$WL_SUB" ] && [ -f "$WL_SUB" ]; then
    info "DNS brute force ($(wc -l < "$WL_SUB" | tr -d ' ') words, wildcard-filtered)"
    : > "$OUT/.brute"
    if have puredns; then
      timeout "$SUB_BRUTE_BUDGET" puredns bruteforce "$WL_SUB" "$TARGET" -r "$OUT/.resolvers" -q 2>/dev/null | sort -u > "$OUT/.brute"
    elif have dnsx; then
      timeout "$SUB_BRUTE_BUDGET" dnsx -silent -d "$TARGET" -w "$WL_SUB" -r "$OUT/.resolvers" -t 200 2>/dev/null | sort -u > "$OUT/.brute"
    fi
    [ -s "$OUT/.brute" ] && { cat "$OUT/.brute" >> "$all"; ok "brute added $(wc -l < "$OUT/.brute" | tr -d ' ') names"; }
    rm -f "$OUT/.brute"
  fi

  # ---- permutations (alterx) resolved live — guarded so it can't explode ----
  if [ "$SUB_PERMUTE" = "1" ] && have alterx && [ "$(wc -l < "$all" | tr -d ' ')" -le 3000 ]; then
    info "permuting known names (alterx) and resolving"
    sort -u "$all" | timeout 60 alterx -silent 2>/dev/null | head -n 200000 > "$OUT/.perm"
    if [ -s "$OUT/.perm" ]; then
      : > "$OUT/.permres"
      if have puredns; then
        timeout "$SUB_BRUTE_BUDGET" puredns resolve "$OUT/.perm" -r "$OUT/.resolvers" -q 2>/dev/null | sort -u > "$OUT/.permres"
      elif have dnsx; then
        timeout "$SUB_BRUTE_BUDGET" dnsx -silent -l "$OUT/.perm" -r "$OUT/.resolvers" -t 200 2>/dev/null | sort -u > "$OUT/.permres"
      fi
      [ -s "$OUT/.permres" ] && { cat "$OUT/.permres" >> "$all"; ok "permutations added $(wc -l < "$OUT/.permres" | tr -d ' ') resolving names"; }
    fi
    rm -f "$OUT/.perm" "$OUT/.permres"
  fi

  sort -u -o "$all" "$all"
  ok "found ${W}$(wc -l < "$all" | tr -d ' ')${N} total unique subdomains -> $all"
  [ ! -s "$all" ] && { warn "no domains found"; return 0; }

  # ---- resolve, then HTTP-probe for genuinely live hosts ----
  : > "$live"
  local resolved="$OUT/.resolved"; : > "$resolved"
  info "resolving DNS"
  if have dnsx; then
    timeout 90 dnsx -silent -l "$all" -r "$OUT/.resolvers" -t 200 -o "$resolved" 2>/dev/null
  else
    timeout 90 xargs -a "$all" -P 60 -I{} sh -c \
      'dig +short +time=2 +tries=1 "$1" 2>/dev/null | grep -qE "^[0-9]" && echo "$1"' _ {} > "$resolved" 2>/dev/null
  fi
  sort -u -o "$resolved" "$resolved" 2>/dev/null
  [ -s "$resolved" ] || cp "$all" "$resolved"
  ok "$(wc -l < "$resolved" | tr -d ' ') resolve to an IP"

  info "probing for live hosts (budget ${DOMAIN_PROBE_BUDGET}s)"
  if [ -n "$HTTPX" ]; then
    # probe BOTH schemes so http-only hosts aren't missed; keep full scheme URLs
    local pt=$(( THREADS > 150 ? 150 : THREADS ))
    run_timed "probing live hosts" "$DOMAIN_PROBE_BUDGET" "$OUT/live_verbose.txt" \
      sh -c "cat '$resolved' | '$HTTPX' -silent -threads $pt -timeout 6 -retries 1 -status-code -title -rl 300 -no-color"
    grep -oE 'https?://[^ ]+' "$OUT/live_verbose.txt" 2>/dev/null | sort -u > "$live"
  else
    warn "ProjectDiscovery httpx not found (install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest)"
  fi
  # Guarantee working_domains.txt holds real URLs (with scheme). If the probe
  # found nothing (or httpx is missing), fall back to https:// on every resolving
  # host so screenshots/dir-brute still have valid targets — never bare hostnames.
  if [ ! -s "$live" ]; then
    warn "probe returned no live URLs — using resolving hosts as https:// candidates"
    sed 's#^#https://#' "$resolved" | sort -u > "$live"
  fi
  rm -f "$resolved"
  ok "${W}$(wc -l < "$live" 2>/dev/null | tr -d ' ')${N} working domains (URLs) -> $live"

  # ---- screenshot every working domain (auto unless disabled) ----
  if [ "$AUTO_SHOTS_MODE1" = "1" ] && [ -s "$live" ]; then
    mode_screenshot "$live"
  else
    ask_screenshots "$live" "domains"
  fi
  rm -f "$OUT/.resolvers"
}

# brute ONE host. ffuf with -ac (auto-calibrate) learns the target's soft-404
# baseline and drops anything that looks like it -> no junk/garbage paths. Falls
# back to feroxbuster then gobuster. Emits clean, code-sorted "CODE  SIZE  URL".
_dir_brute_one(){
  local url="$1" per="$2" wl="$3"
  local safe; safe=$(printf '%s' "$url" | sed 's#https\?://##; s#[/:]#_#g')
  local out="$OUT/dirs/${safe}.txt"; : > "$out"
  local tf="$OUT/dirs/.${safe}.json"
  if have ffuf; then
    ffuf -u "${url%/}/FUZZ" -w "$wl:FUZZ" -ac \
         -mc 200,204,301,302,307,308,401,403,405 -fc 404 -ic \
         -t "$THREADS" -timeout 7 -maxtime "$per" -rate 0 \
         -of json -o "$tf" -s >/dev/null 2>&1
    if [ -s "$tf" ]; then
      if have jq; then
        jq -r '.results[]? | "\(.status)\t\(.length)\t\(.url)"' "$tf" 2>/dev/null | sort -k1,1n -u > "$out"
      else
        grep -oE '"url":"[^"]+"' "$tf" | sed 's/"url":"//; s/"$//' | sort -u > "$out"
      fi
      rm -f "$tf"
    fi
  elif have feroxbuster; then
    timeout "$per" feroxbuster -u "$url" -w "$wl" -t "$THREADS" -k -q -n \
      -C 404,400,500,502,503 2>/dev/null | sort -u > "$out"
  elif have gobuster; then
    timeout "$per" gobuster dir -u "$url" -w "$wl" -t "$THREADS" -q -b 404,400 2>/dev/null | sort -u > "$out"
  fi
  ok "[dir] $safe -> $(wc -l < "$out" 2>/dev/null | tr -d ' ') paths"
}

# =============================================================================
# MODE 2 — FINGERPRINT -> PARALLEL, CLEAN DIRECTORY SEARCH
# =============================================================================
mode_fingerprint_dirs(){
  local live="$OUT/working_domains.txt"
  local tech="$OUT/tech.txt" valuable="$OUT/valuable_targets.txt"

  if [ ! -s "$live" ]; then
    warn "no working_domains.txt yet — probing the base target"
    if [ -n "$HTTPX" ]; then
      printf '%s\n' "$TARGET" | timeout 60 "$HTTPX" -silent -threads "$THREADS" | sort -u > "$live"
    else
      echo "https://$TARGET" > "$live"
    fi
  fi
  info "$(wc -l < "$live" | tr -d ' ') live hosts to fingerprint"

  info "fingerprinting (httpx tech-detect$(have whatweb && printf ' + whatweb'))"
  if [ -n "$HTTPX" ]; then
    run_timed "fingerprinting" 90 "$tech" \
      sh -c "grep -oE 'https?://[^ ]+' '$live' | '$HTTPX' -silent -threads $THREADS -timeout 8 -retries 0 -status-code -title -td -web-server -rl 300 -no-color"
  fi
  have whatweb && timeout 90 whatweb -q --no-errors -i "$live" --log-brief="$OUT/whatweb.txt" >/dev/null 2>&1
  [ ! -s "$tech" ] && [ -s "$OUT/whatweb.txt" ] && cp "$OUT/whatweb.txt" "$tech"
  [ -s "$tech" ] && { ok "fingerprint -> $tech"; sed 's/^/    /' "$tech" | head -25; }

  # rank hosts: interesting tech / auth-gated / error pages first, then the rest
  local pat='WordPress|Jenkins|GitLab|Tomcat|phpMyAdmin|Django|Laravel|Spring|Drupal|Joomla|Grafana|Kibana|Jira|Confluence|Struts|WebLogic|Swagger|GraphQL|Kubernetes|\[40[13]\]|\[500\]'
  : > "$valuable"
  [ -s "$tech" ] && grep -iE "$pat" "$tech" | grep -oE 'https?://[^ ]+' | sort -u > "$valuable"
  { cat "$valuable"; grep -oE 'https?://[^ ]+' "$live"; } | awk '!seen[$0]++' > "$valuable.t" && mv "$valuable.t" "$valuable"
  local HOST_CAP=12
  if [ "$(wc -l < "$valuable" | tr -d ' ')" -gt "$HOST_CAP" ]; then
    head -n "$HOST_CAP" "$valuable" > "$valuable.t"; mv "$valuable.t" "$valuable"
    warn "capping directory brute to $HOST_CAP hosts (valuable ones first)"
  fi
  local n; n=$(wc -l < "$valuable" | tr -d ' '); [ "$n" -lt 1 ] && n=1
  ok "$n target(s) for directory brute -> $valuable"

  local wl="$WL_DIR_SMALL"; [ -f "$WL_DIR_BIG" ] && wl="$WL_DIR_BIG"
  [ -f "$wl" ] || { err "no wordlist found (install seclists or bundle ./wordlists)"; return 1; }
  info "wordlist: $wl ($(wc -l < "$wl" | tr -d ' ') entries)"

  # ---- run several hosts at once; each ffuf is itself multi-threaded ----
  mkdir -p "$OUT/dirs"
  local PAR=4
  local chunks=$(( (n + PAR - 1) / PAR ))
  local per=$(( DIR_BUDGET / chunks )); [ "$per" -lt 60 ] && per=60; [ "$per" -gt 150 ] && per=150
  info "directory brute: $PAR hosts in parallel, ${per}s/host (~${DIR_BUDGET}s total)"

  local i=0
  while IFS= read -r url; do
    [ -z "$url" ] && continue
    i=$((i+1))
    _dir_brute_one "$url" "$per" "$wl" &
    [ $(( i % PAR )) -eq 0 ] && wait
  done < "$valuable"
  wait

  # ---- Google-dork content discovery: indexed = real, so zero-junk paths that
  #      brute force alone would miss. Runs on the top hosts, in parallel. ----
  local dorked="$OUT/dorked_dirs.txt"; : > "$dorked"
  local DORK_HOSTS=5 j=0
  info "google-dorking indexed paths on up to $DORK_HOSTS hosts (Google/Bing/DDG)"
  while IFS= read -r url; do
    [ -z "$url" ] && continue
    j=$((j+1)); [ "$j" -gt "$DORK_HOSTS" ] && break
    local host; host=$(printf '%s' "$url" | sed 's#https\?://##; s#[/:].*##')
    ( _dork_dirs "$host" >> "$dorked" ) &
    [ $(( j % PAR )) -eq 0 ] && wait
  done < "$valuable"
  wait
  sort -u -o "$dorked" "$dorked" 2>/dev/null
  ok "dorking found $(wc -l < "$dorked" 2>/dev/null | tr -d ' ') indexed URLs -> $dorked"

  # ---- merge brute + dork results into one clean, deduped report ----
  local combined="$OUT/all_dirs.txt"
  { cat "$OUT"/dirs/*.txt 2>/dev/null; sed 's/^/DORK\t\t/' "$dorked" 2>/dev/null; } | sort -u > "$combined"
  ok "directory search complete -> $OUT/dirs/ (combined $(wc -l < "$combined" 2>/dev/null | tr -d ' ') paths in all_dirs.txt)"

  ask_screenshots "$valuable" "valuable hosts"
}

# =============================================================================
# MODE 3 — CRAZIER CRAWL  (katana / gau)
# =============================================================================
mode_crawl(){
  local live="$OUT/working_domains.txt"
  local seeds="$OUT/.seeds" urls="$OUT/crawl_urls.txt"
  # seed with the RIGHT scheme: reuse live URLs, else probe the target so we don't
  # crawl https:// on an http-only host (a common reason mode 3 found nothing).
  if [ -s "$live" ]; then
    cp "$live" "$seeds"
  elif [ -n "$HTTPX" ]; then
    printf '%s\n' "$TARGET" | timeout 30 "$HTTPX" -silent -timeout 5 -retries 0 2>/dev/null | sort -u > "$seeds"
    [ -s "$seeds" ] || printf 'http://%s\n' "$TARGET" > "$seeds"
  else
    printf 'http://%s\n' "$TARGET" > "$seeds"
  fi
  info "crawling $(wc -l < "$seeds") seed host(s) (TOTAL budget ${CRAWL_BUDGET}s, live progress below)"
  : > "$urls"
  local t0=$SECONDS   # whole mode (katana + gau) must finish within CRAWL_BUDGET

  # --- active crawl: katana. JACKAL_HEADLESS=1 renders JS (needed for SPA sites
  #     that expose no static <a href> links — a common reason katana returns ~0). ---
  if have katana; then
    local kflags="-jc -kf all -d 3 -c $THREADS -aff"
    if [ "${JACKAL_HEADLESS:-0}" = "1" ]; then
      info "engine: katana (HEADLESS / JS-render, depth 3)"
      run_timed "katana crawling" "$CRAWL_BUDGET" "$urls.k" \
        katana -silent -list "$seeds" -headless -no-sandbox $kflags
    else
      info "engine: katana (static, depth 3) — set JACKAL_HEADLESS=1 for JS-heavy sites"
      run_timed "katana crawling" "$CRAWL_BUDGET" "$urls.k" \
        katana -silent -list "$seeds" $kflags
    fi
    cat "$urls.k" >> "$urls" 2>/dev/null; rm -f "$urls.k"
  elif have hakrawler; then
    run_timed "hakrawler crawling" "$CRAWL_BUDGET" "$urls.h" sh -c "cat '$seeds' | hakrawler -d 3"
    cat "$urls.h" >> "$urls" 2>/dev/null; rm -f "$urls.h"
  fi

  # --- passive URLs: gau (wayback + commoncrawl + OTX). Gets only the time LEFT in
  #     the total budget, so the whole mode stays within CRAWL_BUDGET. ---
  if have gau; then
    local remain=$(( CRAWL_BUDGET - (SECONDS - t0) ))
    if [ "$remain" -lt 10 ]; then
      warn "budget spent by katana (${CRAWL_BUDGET}s) — skipping gau"
    else
      local apex; apex=$(sed -E 's#https?://##; s#/.*##; s#:.*##' "$seeds" | sort -u)
      info "engine: gau (passive wayback/commoncrawl/otx, ${remain}s left)"
      run_timed "gau passive" "$remain" "$urls.g" \
        sh -c "printf '%s\n' $apex | gau --threads $THREADS --subs"
      cat "$urls.g" >> "$urls" 2>/dev/null; rm -f "$urls.g"
    fi
  fi

  [ -s "$urls" ] || { warn "no URLs found — site may be down, JS-only, or blocking crawlers (try JACKAL_HEADLESS=1)"; }
  sort -u -o "$urls" "$urls" 2>/dev/null
  rm -f "$seeds"
  ok "$(wc -l < "$urls" 2>/dev/null || echo 0) urls -> $urls"

  grep -iE '\?' "$urls" 2>/dev/null | sort -u > "$OUT/urls_with_params.txt"
  grep -iE '\.js(\?|$)' "$urls" 2>/dev/null | sort -u > "$OUT/js_files.txt"
  grep -iE '/api/|/v[0-9]+/|\.json(\?|$)|graphql' "$urls" 2>/dev/null | sort -u > "$OUT/api_endpoints.txt"
  ok "params: $(wc -l < "$OUT/urls_with_params.txt" 2>/dev/null||echo 0)  js: $(wc -l < "$OUT/js_files.txt" 2>/dev/null||echo 0)  api: $(wc -l < "$OUT/api_endpoints.txt" 2>/dev/null||echo 0)"

  ask_screenshots "$urls" "crawled URLs"
}

# after a mode finishes, offer to screenshot its working results.
#   ask_screenshots <source_file> <label>
# behaviour:  -s flag / JACKAL_SHOTS=1  -> always yes (non-interactive)
#             a tty                      -> prompt y/N
#             otherwise (batch, no -s)   -> skip with a hint
ask_screenshots(){
  local src="$1" label="$2"
  [ -s "$src" ] || return 0
  local n; n=$(grep -cE '^https?://|[a-z]' "$src" 2>/dev/null)
  if [ "${JACKAL_SHOTS:-0}" = "1" ]; then
    :
  elif [ -t 0 ]; then
    echo
    read -r -p "$(printf '%s[?]%s Take screenshots of the %s working %s? [y/N] ' "$C" "$N" "$n" "$label")" a
    case "$a" in y|Y|yes) ;; *) info "skipped screenshots"; return 0;; esac
  else
    info "screenshots available for $label — re-run with -s (or menu) to capture"
    return 0
  fi
  mode_screenshot "$src"
}

# =============================================================================
# MODE 4 — SCREENSHOT working URLs (gowitness -> aquatone -> httpx)
# =============================================================================
mode_screenshot(){
  local ss="$OUT/screenshots"
  # explicit source arg, else crawled URLs, else the live hosts from mode 1
  local src="${1:-}"
  [ -n "$src" ] && [ -s "$src" ] || { src="$OUT/crawl_urls.txt"; [ -s "$src" ] || src="$OUT/working_domains.txt"; }
  # standalone `-m 4`: this run's dir is empty, so reuse the newest PRIOR run that has data
  if [ ! -s "$src" ]; then
    local prev
    for prev in $(ls -dt "$RESULTS_DIR/${TARGET}_"* 2>/dev/null); do
      [ "$prev" = "$OUT" ] && continue
      if [ -s "$prev/crawl_urls.txt" ]; then src="$prev/crawl_urls.txt"; info "reusing $prev"; break; fi
      if [ -s "$prev/working_domains.txt" ]; then src="$prev/working_domains.txt"; info "reusing $prev"; break; fi
    done
  fi
  if [ ! -s "$src" ]; then
    warn "nothing to screenshot yet (run mode 1 or 3 first for $TARGET)"; return 0
  fi
  local chrome=""
  for c in chromium chromium-browser google-chrome google-chrome-stable chrome brave-browser; do
    have "$c" && { chrome="$(command -v "$c")"; break; }
  done
  # macOS installs browsers as .app bundles that aren't on PATH — check those too
  if [ -z "$chrome" ]; then
    local p
    for p in \
      "/Applications/Chromium.app/Contents/MacOS/Chromium" \
      "$HOME/Applications/Chromium.app/Contents/MacOS/Chromium" \
      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
      "$HOME/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
      "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser" \
      "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"; do
      [ -x "$p" ] && { chrome="$p"; break; }
    done
  fi
  [ -z "$chrome" ] && { err "no chromium/chrome found — install: brew install --cask chromium"; return 1; }
  info "browser: $chrome"

  mkdir -p "$ss"
  local list="$OUT/.shotlist"
  # normalise: keep scheme'd URLs as-is; prefix https:// onto bare hostnames so a
  # working_domains.txt of plain hosts still gets screenshotted (no more skips)
  awk 'NF && $0 !~ /^[[:space:]]*#/ { if ($0 ~ /^https?:\/\//) print; else print "https://" $0 }' \
    "$src" 2>/dev/null | sort -u > "$list"
  local total; total=$(wc -l < "$list")
  [ "$total" -eq 0 ] && { warn "no hosts/URLs in $(basename "$src")"; rm -f "$list"; return 0; }
  if [ "$total" -gt "$SHOT_CAP" ]; then
    warn "capping at $SHOT_CAP of $total URLs (raise SHOT_CAP to change)"
    head -n "$SHOT_CAP" "$list" > "$list.t" && mv "$list.t" "$list"; total=$SHOT_CAP
  fi
  info "screenshotting up to $total working URL(s) -> $ss/ (budget ${SHOT_BUDGET}s)"

  if have gowitness; then
    info "engine: gowitness"
    ( timeout "$SHOT_BUDGET" gowitness scan file -f "$list" \
        --screenshot-path "$ss" --chrome-path "$chrome" >/dev/null 2>&1 ) &
  elif have aquatone; then
    info "engine: aquatone"
    ( timeout "$SHOT_BUDGET" sh -c "cat '$list' | aquatone -out '$ss' -chrome-path '$chrome' -silent" >/dev/null 2>&1 ) &
  else
    info "engine: httpx -screenshot"
    ( timeout "$SHOT_BUDGET" sh -c "cat '$list' | '$HTTPX' -silent -ss -system-chrome \
        -srd '$ss' -threads 10 -timeout 10 -screenshot-timeout 12 -retries 0 -ho '--no-sandbox' -esb" >/dev/null 2>&1 ) &
  fi
  local pid=$! s=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r%s[*]%s screenshotting  %ds · %s captured%s" "$C" "$N" "$s" \
      "$(find "$ss" -type f \( -iname '*.png' -o -iname '*.jpg' -o -iname '*.jpeg' \) 2>/dev/null | wc -l)" "$(printf '\033[K')"
    sleep 3; s=$((s+3))
  done
  wait "$pid" 2>/dev/null
  printf "\r%s" "$(printf '\033[K')"
  rm -f "$list"

  local shots; shots=$(find "$ss" -type f \( -iname '*.png' -o -iname '*.jpg' -o -iname '*.jpeg' \) 2>/dev/null | wc -l)
  ok "$shots screenshot(s) saved under $ss/"
  if [ "$shots" -gt 0 ]; then
    {
      echo "<html><meta charset=utf-8><title>jackalhunt shots — $TARGET</title>"
      echo "<body style='font-family:sans-serif;background:#111;color:#eee;margin:16px'>"
      echo "<h2>jackalhunt screenshots — $TARGET ($shots)</h2>"
      find "$ss" -type f \( -iname '*.png' -o -iname '*.jpg' -o -iname '*.jpeg' \) | sort | while read -r p; do
        local rel="${p#"$ss"/}"
        printf "<div style='display:inline-block;margin:6px;text-align:center;vertical-align:top'><a href='%s'><img src='%s' style='width:320px;border:1px solid #333' loading='lazy'></a><br><span style='font-size:11px'>%s</span></div>\n" "$rel" "$rel" "$rel"
      done
      echo "</body></html>"
    } > "$ss/gallery.html" 2>/dev/null
    ok "open gallery: $ss/gallery.html"
  fi
}

# =============================================================================
# menu
# =============================================================================
run_all(){ mode_domains && mode_fingerprint_dirs && mode_crawl; }

menu(){
  banner
  printf "  %s1)%s Domain search        (~5 min)  all_domains + working_domains\n" "$W" "$N"
  printf "  %s2)%s Fingerprint + dirs   (~10 min) tech-detect -> valuable -> brute\n" "$W" "$N"
  printf "  %s3)%s Crazier crawl        (katana)  urls, params, js, api (+screenshots)\n" "$W" "$N"
  printf "  %s4)%s Screenshot URLs      (chrome)  shoot working crawled URLs -> gallery\n" "$W" "$N"
  printf "  %s5)%s Run all (1 -> 2 -> 3)\n" "$W" "$N"
  printf "  %sq)%s quit\n\n" "$W" "$N"
  read -r -p "$(printf '%s[?]%s choose: ' "$C" "$N")" choice
  case "$choice" in
    1) mode_domains ;;
    2) mode_fingerprint_dirs ;;
    3) mode_crawl ;;
    4) mode_screenshot ;;
    5) run_all ;;
    q|Q) exit 0 ;;
    *) err "invalid choice" ;;
  esac
}

usage(){
  cat <<EOF
jackalhunt — time-boxed recon orchestrator
usage: $0 [-t target[,target2,...]] [-l file] [-m 1|2|3|4|all] [-y] [-s]
  -t   target domain(s), comma-separated (e.g. a.com,b.com); prompted if omitted
  -l   file with one domain/subdomain per line (# and blank lines ignored)
  -m   run a mode non-interactively: 1, 2, 3, 4 (screenshots), or all
  -y   skip authorization prompt (JACKAL_YES=1)
  -s   auto-take screenshots after each mode (else you're asked per mode; needs a tty)
examples:
  $0                              # interactive menu
  $0 -t example.com -m 1          # domain search, then asks to screenshot
  $0 -t example.com -m 1 -s       # domain search + auto-screenshot working domains
  $0 -t a.com,b.com,c.com -m all -y -s  # several targets, full chain, auto-shots
  $0 -l scope.txt -m 1 -y         # scan every domain/subdomain in scope.txt
each target gets its own results/<target>_<timestamp>/ folder.
EOF
}

# run a single mode against the CURRENT target (set by set_target)
dispatch(){
  case "$1" in
    1)   mode_domains ;;
    2)   mode_fingerprint_dirs ;;
    3)   mode_crawl ;;
    4)   mode_screenshot ;;
    all) run_all ;;
    *)   err "unknown mode: $1"; return 1 ;;
  esac
}

# ----------------------------------------------------------------------------- main
main(){
  mkdir -p "$RESULTS_DIR"
  resolve_httpx || true
  _resolve_wordlists
  local target="" listfile="" mode=""
  while getopts ":t:l:m:ysh" opt; do
    case "$opt" in
      t) target="$OPTARG" ;;
      l) listfile="$OPTARG" ;;      # file with one domain/subdomain per line
      m) mode="$OPTARG" ;;
      y) JACKAL_YES=1 ;;
      s) JACKAL_SHOTS=1 ;;          # auto-take screenshots (no prompt) in each mode
      h) usage; exit 0 ;;
      *) usage; exit 1 ;;
    esac
  done

  # ---- build the target list from -t (comma ok), -l <file>, or a prompt ----
  local targets="$RESULTS_DIR/.targets.$$"; : > "$targets"
  [ -n "$target" ]  && printf '%s\n' "$target" | tr ',' '\n' >> "$targets"
  if [ -n "$listfile" ]; then
    [ -r "$listfile" ] || { err "cannot read list file: $listfile"; exit 1; }
    grep -vE '^\s*(#|$)' "$listfile" >> "$targets"     # skip blanks/comments
  fi
  if [ ! -s "$targets" ]; then
    banner
    read -r -p "$(printf '%s[?]%s target domain (or comma-separated list): ' "$C" "$N")" target
    printf '%s\n' "$target" | tr ',' '\n' >> "$targets"
  fi
  # normalize: strip scheme/path, lowercase, dedupe
  sed -E 's#https?://##; s#/.*##' "$targets" | tr '[:upper:]' '[:lower:]' \
    | sed -E 's/^\s+//; s/\s+$//' | grep -E '.' | sort -u > "$targets.n" && mv "$targets.n" "$targets"
  local ntargets; ntargets=$(wc -l < "$targets")
  [ "$ntargets" -eq 0 ] && { err "no valid targets"; rm -f "$targets"; exit 1; }

  [ -n "$HTTPX" ] && info "httpx: $HTTPX" || warn "httpx: ProjectDiscovery build not found (using fallbacks)"
  ok "$ntargets target(s) queued"

  # one authorization confirmation for the whole batch
  if [ "${JACKAL_YES:-0}" != "1" ]; then
    warn "Only scan assets you own or are explicitly authorized to test."
    sed 's/^/      /' "$targets"
    read -r -p "$(printf '%s[?]%s Confirm you are authorized for all %s target(s)? [y/N] ' "$Y" "$N" "$ntargets")" a
    case "$a" in y|Y|yes) ;; *) err "aborted"; rm -f "$targets"; exit 1;; esac
    JACKAL_YES=1
  fi

  # ---- single target + no mode -> interactive menu (original behavior) ----
  if [ "$ntargets" -eq 1 ] && [ -z "$mode" ]; then
    set_target "$(cat "$targets")"; rm -f "$targets"
    while true; do echo; menu; done
  fi

  # ---- batch: pick a mode once (menu) if not given, then loop every target ----
  if [ -z "$mode" ]; then
    banner
    printf "  %s1)%s Domain search   %s2)%s Fingerprint+dirs   %s3)%s Crawl+shots   %s4)%s Screenshots   %sall)%s Everything\n" "$W" "$N" "$W" "$N" "$W" "$N" "$W" "$N" "$W" "$N"
    read -r -p "$(printf '%s[?]%s mode for all %s targets: ' "$C" "$N" "$ntargets")" mode
  fi

  local i=0
  while read -r t; do
    i=$((i+1))
    printf "\n%s========== [%s/%s] %s ==========%s\n" "$C$W" "$i" "$ntargets" "$t" "$N"
    set_target "$t" && dispatch "$mode"
  done < "$targets"
  rm -f "$targets"
  ok "batch complete: $ntargets target(s) processed under $RESULTS_DIR/"
}
main "$@"
