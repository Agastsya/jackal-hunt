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
BASE_DIR="${JACKAL_HOME:-$HOME/recon}"
RESULTS_DIR="$BASE_DIR/results"
PATH="$HOME/go/bin:$PATH"     # PREPEND go tools so PD httpx beats /bin/httpx (python)
# macOS ships without GNU timeout/stdbuf/nproc; `brew install coreutils` provides
# them under a gnubin dir by their normal names. Prepend it so they resolve
# directly AND compose (e.g. `timeout ... stdbuf ...`) — a shell-function shim
# can't do that, since timeout execs its args and never sees a bash function.
for _gnubin in /opt/homebrew/opt/coreutils/libexec/gnubin /usr/local/opt/coreutils/libexec/gnubin; do
  [ -d "$_gnubin" ] && PATH="$_gnubin:$PATH"
done
export PATH

# time budgets (seconds)
DOMAIN_ENUM_BUDGET=240        # mode 1: enumeration
DOMAIN_PROBE_BUDGET=90        # mode 1: live probing
DIR_BUDGET=600                # mode 2: directory brute total (10 min)
CRAWL_BUDGET=200              # mode 3: TOTAL budget (katana + gau share this, seconds)
SHOT_BUDGET=600               # mode 4: screenshotting crawled URLs (10 min)
SHOT_CAP=150                  # max URLs to screenshot in one run

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

# =============================================================================
# MODE 1 — DOMAIN SEARCH  (<= ~5 min)
# =============================================================================
mode_domains(){
  local all="$OUT/all_domains.txt" live="$OUT/working_domains.txt"
  : > "$OUT/.raw"
  info "enumerating subdomains for $TARGET (budget ${DOMAIN_ENUM_BUDGET}s)"

  ( have subfinder && timeout "$DOMAIN_ENUM_BUDGET" subfinder -silent -all -d "$TARGET" 2>/dev/null ) >> "$OUT/.raw" &
  local p1=$!
  (
    timeout 60 curl -s "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null \
      | grep -oE '"common_name":"[^"]+"|"name_value":"[^"]+"' \
      | sed -E 's/.*":"//; s/"$//; s/\\n/\n/g' | sed 's/^\*\.//'
  ) >> "$OUT/.raw" &
  local p2=$!
  ( have assetfinder && timeout "$DOMAIN_ENUM_BUDGET" assetfinder --subs-only "$TARGET" 2>/dev/null ) >> "$OUT/.raw" &
  local p3=$!

  # --- Wayback Machine (CDX API, no key) : every host ever archived under the domain ---
  (
    timeout 90 curl -s \
      "http://web.archive.org/cdx/search/cdx?url=${TARGET}&matchType=domain&fl=original&collapse=urlkey&output=text" \
      2>/dev/null | grep -oE 'https?://[^/]+' | sed -E 's#https?://##; s#:[0-9]+$##'
  ) >> "$OUT/.raw" &
  local p4=$!

  # --- Shodan DNS (needs SHODAN_API_KEY env or ~/.config/shodan/api_key) ---
  local skey="${SHODAN_API_KEY:-$(cat "$HOME/.config/shodan/api_key" 2>/dev/null)}"
  if [ -n "$skey" ]; then
    (
      timeout 60 curl -s "https://api.shodan.io/dns/domain/${TARGET}?key=${skey}" 2>/dev/null \
        | grep -oE '"subdomains":\[[^]]*\]' | grep -oE '"[^"]+"' | tr -d '"' \
        | grep -v '^subdomains$' | sed "s/\$/.${TARGET}/"
    ) >> "$OUT/.raw" &
  else
    warn "Shodan skipped (set SHODAN_API_KEY or run 'shodan init <key>' to enable)"
    ( : ) &
  fi
  local p5=$!

  # heartbeat while the passive sources run, so it never looks frozen
  local s=0
  while kill -0 $p1 2>/dev/null || kill -0 $p2 2>/dev/null || kill -0 $p3 2>/dev/null \
     || kill -0 $p4 2>/dev/null || kill -0 $p5 2>/dev/null; do
    printf "\r%s[*]%s enumerating (subfinder·crt.sh·wayback·shodan)  %ds · %s raw%s" \
      "$C" "$N" "$s" "$(sort -u "$OUT/.raw" 2>/dev/null | wc -l)" "$(printf '\033[K')"
    sleep 3; s=$((s+3))
  done
  printf "\r%s" "$(printf '\033[K')"
  wait $p1 $p2 $p3 $p4 $p5 2>/dev/null

  {
    grep -oE '[a-zA-Z0-9._-]+\.'"$(printf '%s' "$TARGET" | sed 's/\./\\./g')" "$OUT/.raw"
    printf '%s\n' "$TARGET"          # always include the apex itself
  } | tr '[:upper:]' '[:lower:]' | sort -u > "$all"
  rm -f "$OUT/.raw"
  ok "found $(wc -l < "$all") unique domains -> $all"
  [ ! -s "$all" ] && { warn "no domains found"; return 0; }

  : > "$live"                       # guarantee the file exists even if nothing is live

  # prune to hosts that actually resolve, so the HTTP probe isn't wasted on dead
  # DNS (crt.sh returns plenty of junk). This is fast and parallel.
  local resolved="$OUT/.resolved"; : > "$resolved"
  info "resolving DNS (parallel)"
  if have dnsx; then
    timeout 60 dnsx -silent -l "$all" -o "$resolved" 2>/dev/null
  else
    timeout 60 xargs -a "$all" -P 50 -I{} sh -c \
      'dig +short +time=2 +tries=1 "$1" 2>/dev/null | grep -qE "^[0-9]" && echo "$1"' _ {} \
      > "$resolved" 2>/dev/null
  fi
  sort -u -o "$resolved" "$resolved" 2>/dev/null
  [ -s "$resolved" ] || cp "$all" "$resolved"   # fall back to full list if prune yielded nothing
  ok "$(wc -l < "$resolved") resolve to an IP"

  info "probing for live hosts (budget ${DOMAIN_PROBE_BUDGET}s)"
  if [ -n "$HTTPX" ]; then
    # Notes learned the hard way:
    #  - httpx -o can lose buffered results if `timeout` SIGKILLs it, so we stream
    #    stdout through stdbuf (line-buffered) into the file -> partial hits survive.
    #  - -timeout 5 -retries 0 abandons a hanging/tarpit host fast (no wasted budget).
    #  - keep it to -status-code here (fast); titles/tech come in mode 2.
    # feed via stdin, NOT -l: httpx's -l mode deadlocks on stdin when stdout is a pipe/file
    local pt=$(( THREADS > 60 ? 60 : THREADS ))
    run_timed "probing live hosts" "$DOMAIN_PROBE_BUDGET" "$OUT/live_verbose.txt" \
      sh -c "cat '$resolved' | '$HTTPX' -silent -threads $pt -timeout 5 -retries 0 -status-code"
    grep -oE 'https?://[^ ]+' "$OUT/live_verbose.txt" 2>/dev/null | sort -u > "$live"
    rm -f "$resolved"
  else
    warn "ProjectDiscovery httpx not found; falling back to dig resolution check"
    warn "install it: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
    cp "$resolved" "$live"        # already resolved above; treat resolvable as "working"
    rm -f "$resolved"
  fi
  ok "$(wc -l < "$live" 2>/dev/null || echo 0) working domains -> $live"

  ask_screenshots "$live" "domains"
}

# =============================================================================
# MODE 2 — FINGERPRINT -> EXTENSIVE DIRECTORY SEARCH  (<= ~10 min)
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
  info "$(wc -l < "$live") live hosts to fingerprint"

  info "fingerprinting (httpx tech-detect + whatweb)"
  if [ -n "$HTTPX" ]; then
    # stdin-fed (see mode 1 note); -title/-tech-detect read bodies so allow a longer timeout
    run_timed "fingerprinting" 120 "$tech" \
      sh -c "grep -oE 'https?://[^ ]+' '$live' | '$HTTPX' -silent -threads $THREADS -timeout 8 -retries 0 -status-code -title -tech-detect -web-server"
  fi
  if have whatweb; then
    timeout 120 whatweb -q --no-errors -i "$live" --log-brief="$OUT/whatweb.txt" >/dev/null 2>&1
  fi
  # tech may come from httpx OR whatweb; ensure we have something to select from
  [ ! -s "$tech" ] && [ -s "$OUT/whatweb.txt" ] && cp "$OUT/whatweb.txt" "$tech"
  [ -s "$tech" ] && { ok "fingerprint -> $tech"; sed 's/^/    /' "$tech" | head -30; }

  local pat='WordPress|Jenkins|GitLab|Tomcat|phpMyAdmin|Django|Laravel|Spring|Drupal|Joomla|Grafana|Kibana|Jira|Confluence|Struts|WebLogic|401|403|500'
  if [ -s "$tech" ]; then
    grep -iE "$pat" "$tech" | grep -oE 'https?://[^ ]+' | sort -u > "$valuable"
  fi
  [ ! -s "$valuable" ] && grep -oE 'https?://[^ ]+' "$live" | sort -u > "$valuable"
  local n; n=$(wc -l < "$valuable"); [ "$n" -lt 1 ] && n=1
  ok "$n valuable target(s) selected -> $valuable"

  local wl="$WL_DIR_SMALL"
  [ -f "$WL_DIR_BIG" ] && wl="$WL_DIR_BIG"
  [ -f "$wl" ] || { err "no wordlist found (install seclists)"; return 1; }
  info "wordlist: $wl"

  local per=$(( DIR_BUDGET / n )); [ "$per" -lt 45 ] && per=45
  local cap=8
  info "directory brute: ${per}s/host, up to $cap hosts (total cap ${DIR_BUDGET}s)"

  mkdir -p "$OUT/dirs"
  local i=0
  while read -r url; do
    [ -z "$url" ] && continue
    i=$((i+1)); [ "$i" -gt "$cap" ] && { warn "host cap reached"; break; }
    local safe; safe=$(echo "$url" | sed 's#https\?://##; s#[/:]#_#g')
    local hit="$OUT/dirs/${safe}.txt"
    # each tool prints found paths to stdout -> run_timed streams them with a live counter
    if have feroxbuster; then
      run_timed "[$i/$n] brute $url" "$per" "$hit" feroxbuster -u "$url" -w "$wl" -t "$THREADS" -q -k
    elif have ffuf; then
      run_timed "[$i/$n] brute $url" "$per" "$hit" ffuf -u "${url%/}/FUZZ" -w "$wl" -t "$THREADS" \
        -mc 200,204,301,302,307,401,403,405 -s
    elif have gobuster; then
      run_timed "[$i/$n] brute $url" "$per" "$hit" gobuster dir -u "$url" -w "$wl" -t "$THREADS" -q
    else
      err "no directory bruteforcer available (ffuf/feroxbuster/gobuster)"; break
    fi
    ok "[$i/$n] $url -> $(wc -l < "$hit" 2>/dev/null || echo 0) paths in ${safe}.txt"
  done < "$valuable"
  ok "directory search complete -> $OUT/dirs/"

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
  for c in chromium chromium-browser google-chrome chrome; do
    have "$c" && { chrome="$(command -v "$c")"; break; }
  done
  [ -z "$chrome" ] && { err "no chromium/chrome found — needed for screenshots"; return 1; }

  mkdir -p "$ss"
  local list="$OUT/.shotlist"
  grep -E '^https?://' "$src" 2>/dev/null | sort -u > "$list"
  local total; total=$(wc -l < "$list")
  [ "$total" -eq 0 ] && { warn "no http(s) URLs in $(basename "$src")"; rm -f "$list"; return 0; }
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
