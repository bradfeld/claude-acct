#!/bin/bash
# claude-acct.sh — switch the Claude account every Claude Code session on this machine uses,
# and bring up the matching Chrome profile, in one command.
#
# MECHANISM: an account is TWO records, and a switch moves both.
#   1. The TOKEN — key `claudeAiOauth` of the macOS Keychain item `Claude Code-credentials`,
#      plus `-<sha256($CLAUDE_CONFIG_DIR)[0:8]>` when that variable is set, account `$USER`. It carries
#      no identity: its keys are accessToken, expiresAt, rateLimitTier, refreshToken,
#      refreshTokenExpiresAt, scopes, subscriptionType, subscriptionTypeSource. The same item
#      also holds every MCP server's OAuth login, which is per-machine, so only `claudeAiOauth`
#      moves and every other key stays exactly as it was. Swapping the whole item would log
#      every MCP server out, or into the wrong account's grants.
#   2. The IDENTITY — `oauthAccount` in `$CLAUDE_CONFIG_DIR/.claude.json`, or `~/.claude.json`
#      when the variable is unset (email, account and org ids). `claude auth status` and the API's user attribution read it, not the token.
#      Moving the token alone leaves Claude Code naming the old account over the new token.
# Each account is parked in its own slot item (`claude-acct/<email>`) as
# `{claudeAiOauth, oauthAccount}`. A slot saved before identity slots carries the token only; `use`
# refuses it, because the identity cannot be derived from the token.
#
# The .claude.json write takes Claude Code's own config lock (`.claude.json.lock`, a
# proper-lockfile mkdir lock — measured from the CLI 2.1.312 binary), re-reads the file under
# it, changes `oauthAccount` only, and replaces the file by temp file + rename. Running
# sessions write that file often; they take the same lock and re-read before writing, so this
# serializes with them and keeps whatever they wrote.
#
# Why in place, not a second CLAUDE_CONFIG_DIR: that variable relocates the whole machine
# surface (hooks, rules, settings, transcripts), and a login written under one config-dir string
# is invisible to sessions that resolved another (the Keychain service name hashes the string).
#
# WHERE THINGS LIVE, read from the CLI 2.1.314 binary: with CLAUDE_CONFIG_DIR set, the Keychain
# service carries the hash suffix and the identity is in that dir's .claude.json. Unset, the
# service has no suffix and the identity is in ~/.claude.json. CLAUDE_SECURESTORAGE_CONFIG_DIR,
# when set, overrides the Keychain half only (empty = no suffix).
#
# WHO MOVES: every session. A NEW session starts on the new account; a RUNNING one adopts it at
# its next request, because before each request Claude Code re-reads the keychain login and takes
# a changed one (the CLI's "sibling login" adoption, read from the 2.1.317 binary). Measured
# 2026-11-04 with no restart: three running sessions' 7-day quota readings moved to the new
# account's window within about two minutes of a `use`. (An earlier opposite reading came from
# an analytics user.email label, not the token a request is sent with.) An idle session moves
# when next used. For one that did not, `/exit` then `claude --continue` moves it with its
# conversation intact.
# A plaintext `<config dir>/.credentials.json` breaks the adoption (sessions watch that file
# instead of the keychain); keep it absent (a launchd WatchPaths job works), and `use` warns if present.
#
# NEVER PRINTS A CREDENTIAL. Values are read into variables and moved through pipes. Writes use
# Claude Code's own transport (see kc_write): stdin when it fits, `-X <hex>` in argv when it does
# not — so a large item is briefly visible to same-user `ps`, as it already is on every refresh
# Claude Code does. Every write is read back; a failed switch restores BOTH records.
#
# RESIDUAL: nothing makes the keychain write and the .claude.json write one atomic step, and
# Claude Code takes no lock on the keychain item. A running session still holding the old
# account can write it back — a token refresh into the keychain, or its in-memory identity into
# .claude.json through its own config writer. The post-switch `claude auth status` check proves
# the switch landed; it cannot prove a later write by such a session will not undo it.
# `use` re-reads the live item just before its write and again before a rollback's write, and
# abandons or re-classifies when the bytes moved. That narrows the refresh race; it does not
# close it: the keychain has no compare-and-swap, so a refresh can still land between the last
# read and the write. Every failure path classifies the live item's `claudeAiOauth` (damaged ·
# the original · the new one · foreign) and never overwrites a token it did not write.
# A SECOND residual: a token carries no identity. `read_live_as` proves the identity record and
# the status label, not who owns the token bytes, so a session still holding another account's
# login can write that token over the live item and `use` would park it under the identity's
# slot. Nothing local can name a token's owner; watching each session's quota readings after a
# switch (they move to the new account's reset window) is how a caller detects that case.
#
# Usage:
#   claude-acct.sh whoami                 the account Claude Code reports (via `claude auth status`)
#   claude-acct.sh save                   park the live token + identity in its slot (run after a login)
#   claude-acct.sh add <email>            save the current account, sign in as <email> in its Chrome
#                                         profile (`claude auth login`, via $BROWSER), save it
#   claude-acct.sh use <alias|email> [--no-chrome] [--expect-from <email>] [--not-after <epoch-seconds>]
#                                         switch; opens the account's Chrome profile unless --no-chrome.
#                                         --expect-from refuses (exit 2) unless <email> is live, read
#                                         under the lock, so a switch planned against a stale view stops.
#                                         --not-after refuses (exit 2) when `date +%s`, read right after
#                                         the lock is taken, is later than <epoch-seconds>: a run either
#                                         took the lock by then or switches nothing (a caller's deadline)
#   claude-acct.sh list [--json]          saved accounts, which one is live, refresh-token expiry;
#                                         --json prints one array (email, alias, live, saved, slot_ok,
#                                         slot_problem, refresh_until, refresh_expired,
#                                         refresh_expires_in_days, chrome_profile, last_resort), no credential
#   claude-acct.sh where                  config_dir= and keychain_account=, the two values that pick the
#                                         credential store, then state_dir=, where the switch log and the
#                                         lock live (reads no credential)
#   claude-acct.sh chrome <alias|email>   open the account's Chrome profile (exit 2 when none is set,
#                                         3 when `open` itself failed)
#   claude-acct.sh limits                 7-day quota per account, from this machine's latest readings
#   claude-acct.sh record-limits          (from a statusline command) keep this payload's reading
#   claude-acct.sh usage [--days N]       token usage per account, attributed by switch time
#   claude-acct.sh --help
#
# Accounts file (optional; aliases, Chrome profiles, last resort): ~/.config/claude-acct/accounts
#   one line per account, tab-separated:  <alias>  <email>  [<chrome profile directory>]  [lastResort]
#   The profile directory is the last segment of "Profile Path" on chrome://version
#   ("Default", "Profile 1", ...). The fourth column is positional and literal: an account with no
#   profile but marked last resort writes an empty third field (alias<TAB>email<TAB><TAB>lastResort).
#
# State: ~/.local/state/claude-acct/switches.jsonl — one line per switch, {ts, from, to}. The
# usage report attributes transcript tokens to whichever account was live at each message.
#
# Guards: an email must be a plain address (it becomes part of a keychain service name, and
# `security -i` re-tokenizes quotes); one save/add/use runs at a time (a lock under the state
# dir: a symlink whose target is the owner's pid, so the pid exists the instant the lock does).
#
# Exit codes: 0 ok · 1 usage error · 2 refused (precondition failed, nothing switched — a slot
#             write that fails is put back, and the message says so if even that fails; for
#             `use` this includes an --expect-from mismatch, a time past --not-after, and a live
#             login that changed before the write) ·
#             3 switch failed and the original token and identity were restored (or the write
#             never landed and nothing changed) ·
#             4 sign in again: the restore ALSO failed (including a live item that could not be
#             read, or kept changing, so nothing was written over it), or a session wrote a token
#             this run never saw ("the token's owner is unknown"), so neither record was rewritten.
#             `list --json` exits 2 when any account cannot be rendered, never printing a short list.

set -u

CCD="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
KC_ACCOUNT="${USER:-$(id -un)}"
# An empty account would read and write keychain items under `-a ""`, which are not Claude Code's
# own, and answer with confidence. `die` is defined below, so this one refusal prints directly.
[ -n "$KC_ACCOUNT" ] || { printf 'claude-acct: USER is unset and id -un named no user — cannot pick the keychain account\n' >&2; exit 2; }
# Hand USER to the `claude` this script runs: with USER unset it finds no claude.ai keychain item,
# so `auth status` names no account (measured under `env -i`, the LaunchAgent environment,
# 2026-11-01). CLAUDE_CONFIG_DIR is passed through only when it was set: exporting the default
# would make `claude` read a suffixed keychain item a stock install never wrote.
export USER="$KC_ACCOUNT"
hash8() { printf '%s' "$1" | shasum -a 256 | cut -c1-8; }
if [ -n "${CLAUDE_SECURESTORAGE_CONFIG_DIR+set}" ]; then
  KC_SUFFIX="${CLAUDE_SECURESTORAGE_CONFIG_DIR:+-$(hash8 "$CLAUDE_SECURESTORAGE_CONFIG_DIR")}"
elif [ -n "${CLAUDE_CONFIG_DIR:-}" ]; then
  KC_SUFFIX="-$(hash8 "$CLAUDE_CONFIG_DIR")"
else
  KC_SUFFIX=""
fi
LIVE_SERVICE="Claude Code-credentials$KC_SUFFIX"
SLOT_PREFIX="claude-acct/"
CONF="${CLAUDE_ACCT_CONF:-$HOME/.config/claude-acct/accounts}"
STATE_DIR="${CLAUDE_ACCT_STATE_DIR:-$HOME/.local/state/claude-acct}"
SWITCHES="$STATE_DIR/switches.jsonl"
if [ -n "${CLAUDE_CONFIG_DIR:-}" ]; then CCJ="$CCD/.claude.json"; else CCJ="$HOME/.claude.json"; fi
CCJ_LOCK_WAIT="${CLAUDE_ACCT_CCJ_LOCK_WAIT:-5}"   # seconds to wait for Claude Code's config lock
# A non-integer would never time out, and a leading zero ("08") is invalid octal to $(( )).
case "$CCJ_LOCK_WAIT" in ''|*[!0-9]*|0[0-9]*) CCJ_LOCK_WAIT=5 ;; esac

die() { printf 'claude-acct: %s\n' "${2:-}" >&2; exit "$1"; }
note() { printf 'claude-acct: %s\n' "$*" >&2; }

usage_text() { sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; }

# ── keychain primitives (never print a value) ────────────────────────────────────────────────
kc_read() {   # $1 service → value on stdout for capture; rc is security's own: 0 found, 44 absent
  # (probed 2026-11-06), anything else a read failure. live_read branches on 44: keep it unmapped.
  security find-generic-password -s "$1" -a "$KC_ACCOUNT" -w 2>/dev/null
}
# Same transport Claude Code itself uses (CLI 2.1.283, its keychain `update`): the payload goes
# through `security -i` on stdin when the command line fits the limit (its constant Bi=4032),
# and as `-X <hex>` in argv when it does not. Measured here: -i silently truncates past that
# length and exits 1; the `-w` stdin prompt keeps only the first 128 bytes. The live item is
# ~6 KB with its MCP logins, so the argv branch is the one that runs for it — exactly as it
# already does on every token refresh Claude Code performs.
# -U keeps the item's access list: measured on a throwaway keychain, the trusted-app list was
# byte-identical before and after an -U update. Claude Code writes this item through
# /usr/bin/security too, so the switch uses the binary the item already trusts.
KC_STDIN_MAX=4032
kc_write() {  # $1 service, value on STDIN → rc 0 only if the read-back hash matches
  local _val _hex _line _want _got
  # The -i branch builds a command line that `security` re-tokenizes, quotes included; a `"`
  # in a service name closes the field and a second `-s` wins (measured: a crafted email wrote
  # an arbitrary item). valid_email is the input boundary; this is the last line behind it.
  case "$1$KC_ACCOUNT" in *[\"\\]*) return 1 ;; esac
  _val=$(cat)
  _hex=$(printf '%s' "$_val" | xxd -p | tr -d '\n')
  [ -n "$_hex" ] || return 1
  _line=$(printf 'add-generic-password -U -a "%s" -s "%s" -X "%s"' "$KC_ACCOUNT" "$1" "$_hex")
  # Strict -lt on purpose: Claude Code compares its line INCLUDING the trailing newline with
  # <= 4032, which is this line without the newline being < 4032.
  if [ "${#_line}" -lt "$KC_STDIN_MAX" ]; then
    printf '%s\n' "$_line" | security -i >/dev/null 2>&1
  else
    security add-generic-password -U -a "$KC_ACCOUNT" -s "$1" -X "$_hex" >/dev/null 2>&1
  fi
  _want=$(printf '%s' "$_val" | tr -d '\n' | shasum -a 256 | cut -c1-16)
  _got=$(kc_read "$1" | tr -d '\n' | shasum -a 256 | cut -c1-16)
  [ "$_want" = "$_got" ]
}

# One `claude auth status` read, classified: `email <addr>`, `out` (logged out), `noemail <method>`
# (logged in, but the CLI named no account), or `unknown` (the call failed or printed no JSON).
# An empty email alone cannot tell the last three apart, and only `out` means "log in" — under a
# LaunchAgent the CLI reported `noemail oauth_token`, and the old message sent a logged-in person
# to log in again.
live_state() {
  local _j _s
  _j=$(claude auth status --json 2>/dev/null) || true
  _s=$(printf '%s' "$_j" | jq -r '
    if type != "object" then "unknown"
    elif .loggedIn == false then "out"
    elif .loggedIn != true then "unknown"
    elif ((.email // "") | type) == "string" and (.email // "") != "" then "email " + .email
    else "noemail " + ((.authMethod // "unknown") | tostring) end' 2>/dev/null) || _s=""
  printf '%s\n' "${_s:-unknown}"
}
live_email() {
  local _s; _s=$(live_state)
  case "$_s" in "email "*) printf '%s\n' "${_s#email }" ;; esac
}
# The live keychain item holds a claude.ai account token. `noemail` alone does not say so: with no
# account signed in under CLAUDE_CONFIG_DIR, the CLI still reports `loggedIn: true` with an
# account-less `oauth_token` (measured 2026-11-01 against an empty config dir).
live_has_account_token() {
  kc_read "$LIVE_SERVICE" 2>/dev/null | part_of claudeAiOauth | grep -q .
}
no_account_why() {  # $1 a live_state value (read afresh when absent) → why no account was named
  local _s="${1:-}"; [ -n "$_s" ] || _s=$(live_state)
  case "$_s" in
    out) printf 'not logged in — run: claude auth login' ;;
    "noemail "*)
      if live_has_account_token; then
        printf 'logged in (%s) but claude auth status names no account — the identity lookup failed, so do not log in again; check USER (%s) and CLAUDE_CONFIG_DIR (%s)' \
          "${_s#noemail }" "$USER" "$CLAUDE_CONFIG_DIR"
      else
        printf 'no claude.ai account is signed in under %s (the CLI holds only an account-less token, authMethod %s) — run: claude auth login' \
          "$CLAUDE_CONFIG_DIR" "${_s#noemail }"
      fi ;;
    "email "*) printf 'the live account read as none, then as %s — retry' "${_s#email }" ;;
    *) printf 'could not ask claude auth status (claude is not on PATH, failed, or printed no JSON)' ;;
  esac
}
confirmed_email() {  # live_email, retried: an empty read is "could not ask", not "wrong account"
  local _e _n=0
  while [ "$_n" -lt 3 ]; do
    _e=$(live_email); [ -n "$_e" ] && { printf '%s\n' "$_e"; return 0; }
    _n=$((_n + 1)); [ "$_n" -lt 3 ] && sleep "${CLAUDE_ACCT_RETRY_SLEEP:-2}"
  done
  return 1
}
valid_email() {  # the input boundary for anything that becomes part of a keychain service name
  printf '%s' "$1" | grep -Eq '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
}
lc() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
part_of() {  # $1 key, stdin: a credential or slot JSON → stdout: that key's object, or nothing
  jq -c --arg k "$1" 'select(type == "object") | .[$k] | select(type == "object")' 2>/dev/null
}
email_of() {  # $1 an oauthAccount JSON → its emailAddress, or nothing
  printf '%s' "$1" | jq -r '.emailAddress // empty' 2>/dev/null
}
same_email() { [ -n "$1" ] && [ "$(lc "$1")" = "$(lc "$2")" ]; }
slot_problem() {  # $1 a slot JSON, $2 its email → nothing if `use` can switch to it, else what is wrong
  # The one definition of a usable slot, shared by `use` (which refuses) and `list` (which says so).
  local _acct
  if [ -z "$(printf '%s' "$1" | part_of claudeAiOauth)" ]; then printf 'not a credential object'
  elif ! _acct=$(printf '%s' "$1" | part_of oauthAccount) || [ -z "$_acct" ]; then printf 'no identity'
  elif ! same_email "$(email_of "$_acct")" "$2"; then printf "identity of '%s'" "$(email_of "$_acct")"
  fi
}

# ── the identity record in .claude.json ─────────────────────────────────────────────────────
live_account() {  # → the live oauthAccount JSON on stdout; rc 1 if the file, the JSON, or the object is missing
  [ -f "$CCJ" ] || return 1
  jq -ce '.oauthAccount | select(type == "object")' "$CCJ" 2>/dev/null
}
ccj_set_account() {  # $1 an oauthAccount JSON → rc 0 only if .claude.json now carries it
  # Under Claude Code's own lock, so a running session's write cannot land between the re-read
  # and the rename. Never steals the lock: a holder past the wait means "failed", and the caller
  # restores. Never creates the file: a missing .claude.json is not ours to invent.
  local _want _lock="$CCJ.lock" _tmp="$CCJ.claude-acct.$$.tmp" _mode _n=0 _rc=1
  _want=$(email_of "$1"); [ -n "$_want" ] && [ -f "$CCJ" ] || return 1
  until mkdir "$_lock" 2>/dev/null; do
    _n=$((_n + 1))
    if [ "$_n" -gt $((CCJ_LOCK_WAIT * 10)) ]; then
      note "Claude Code's config lock ($_lock) was still held after ${CCJ_LOCK_WAIT}s — retry"
      return 1
    fi
    sleep 0.1
  done
  HELD_CCJ_LOCK="$_lock"
  _mode=$(stat -f %Lp "$CCJ" 2>/dev/null) || _mode=600
  if ( umask 077; jq --argjson a "$1" '.oauthAccount = $a' "$CCJ" > "$_tmp" ) 2>/dev/null \
     && [ -s "$_tmp" ] && chmod "$_mode" "$_tmp" && mv -f "$_tmp" "$CCJ"; then
    _rc=0
  else
    note "could not rewrite $CCJ (not valid JSON, or the directory is not writable)"
  fi
  rm -f "$_tmp"
  rmdir "$_lock" 2>/dev/null; HELD_CCJ_LOCK=""
  [ "$_rc" -eq 0 ] && same_email "$(email_of "$(live_account)")" "$_want"
}
# One total classification of the live item against this run's two known credentials.
# The item also holds every MCP login, so the comparison is the WHOLE `claudeAiOauth` object,
# never the whole item (an MCP refresh would read as foreign) and never only accessToken.
live_class() {  # $1 the live item, $2 the new credential, $3 the original → damaged | new | orig | foreign
  local _l _n _o
  _l=$(printf '%s' "$1" | jq -S -c 'select(type == "object") | .claudeAiOauth | select(type == "object")' 2>/dev/null)
  [ -n "$_l" ] || { printf 'damaged\n'; return 0; }
  _n=$(printf '%s' "$2" | jq -S -c '.claudeAiOauth' 2>/dev/null)
  _o=$(printf '%s' "$3" | jq -S -c '.claudeAiOauth' 2>/dev/null)
  if [ "$_l" = "$_n" ]; then printf 'new\n'
  elif [ "$_l" = "$_o" ]; then printf 'orig\n'
  else printf 'foreign\n'; fi
}
foreign_msg() {  # $1 the original account
  printf 'a session wrote the live login during the switch; the token'"'"'s owner is unknown and whoami cannot tell — sign in again: claude auth login --email %s' "$1"
}
# Read the live item into LIVE_BYTES (call directly, never in $(...)). An ABSENT item reads as
# empty, which classifies as damaged: there is no token to lose. Any other read failure is
# rc 1, "unreadable", and callers write nothing: a locked or failing keychain read must never
# turn into a whole-original overwrite of a token this run cannot see.
live_read() {
  local _rc
  LIVE_BYTES=$(kc_read "$LIVE_SERVICE"); _rc=$?
  case "$_rc" in
    0) return 0 ;;
    44) LIVE_BYTES=""; return 0 ;;   # errSecItemNotFound
    *) LIVE_BYTES=""; return 1 ;;
  esac
}
# $1 the original credential, $2 the original oauthAccount, $3 the credential `use` wrote
# → rc 0 both back · 1 the restore failed (nothing was written over bytes it did not read) ·
#   5 a token this run never saw is live (nothing rewritten)
restore_both() {
  local _l _b _w _moved=0
  # Read fresh, classify, compose from that read; re-read just before the write. Bytes that
  # moved get one more classification from the newer read; bytes that move AGAIN are never
  # written over: the newest read decides foreign (5) or a failed restore (1). A change after
  # the last read is the unclosable residual (header, RESIDUAL).
  live_read || return 1; _l="$LIVE_BYTES"
  while :; do
    case "$(live_class "$_l" "$3" "$1")" in
      foreign) return 5 ;;
      orig)    _w="" ;;                  # the token is already the original: identity only
      damaged) _w="$1" ;;                # nothing parseable to keep: the original, whole
      new)     _w=$(printf '%s\n%s\n' "$_l" "$1" | jq -cs '.[0] + {claudeAiOauth: .[1].claudeAiOauth}') \
                 || return 1 ;;          # only the token part goes back; MCP logins stay as found
    esac
    live_read || return 1; _b="$LIVE_BYTES"
    [ "$_b" = "$_l" ] && break
    _moved=$((_moved + 1))
    if [ "$_moved" -ge 2 ]; then
      [ "$(live_class "$_b" "$3" "$1")" = foreign ] && return 5
      return 1
    fi
    _l="$_b"
  done
  # The identity follows the token, never leads it: a token restore that did not land leaves
  # the identity where `use` put it, so the two still name one account.
  if [ -n "$_w" ] && ! printf '%s' "$_w" | kc_write "$LIVE_SERVICE"; then
    # kc_write compares the whole item, so a session refreshing only an MCP login between the
    # write and its read-back fails it although the token landed. Classify, as the forward
    # path does: the original token is live → go on to the identity; foreign → 5; else failed.
    live_read || return 1
    case "$(live_class "$LIVE_BYTES" "$3" "$1")" in
      orig) ;;
      foreign) return 5 ;;
      *) return 1 ;;
    esac
  fi
  # Only rewrite the identity if it moved: a write that never landed needs no undo, and an
  # unconditional rewrite would turn "the write failed" into "the restore failed" (exit 4).
  if [ "$(live_account | jq -cS . 2>/dev/null)" != "$(printf '%s' "$2" | jq -cS .)" ]; then
    ccj_set_account "$2" || return 1
  fi
  return 0
}

# ── accounts file ───────────────────────────────────────────────────────────────────────────
resolve_email() {  # alias or email → a VALIDATED email; a malformed accounts row fails here too
  local _e
  case "$1" in
    *@*) _e="$1" ;;
    *) [ -r "$CONF" ] || return 1
       _e=$(awk -F'\t' -v a="$1" '$1 == a { print $2; found=1; exit } END { exit !found }' "$CONF") \
         || return 1 ;;
  esac
  valid_email "$_e" || return 1
  printf '%s\n' "$_e"
}
chrome_profile_of() {
  [ -r "$CONF" ] || return 1
  awk -F'\t' -v e="$1" '$2 == e && $3 != "" { print $3; found=1; exit } END { exit !found }' "$CONF"
}
alias_of() {  # $1 email → its alias from the accounts file; rc 1 when it has none
  [ -r "$CONF" ] || return 1
  awk -F'\t' -v e="$1" '$1 !~ /^#/ && $2 == e && $1 != "" { print $1; found=1; exit } END { exit !found }' "$CONF"
}
last_resort_of() {  # $1 email → rc 0 when its fourth column is the literal `lastResort`
  [ -r "$CONF" ] || return 1
  awk -F'\t' -v e="$1" '$1 !~ /^#/ && $2 == e && $4 == "lastResort" { found=1; exit } END { exit !found }' "$CONF"
}
open_chrome_for() {  # $1 email → open its Chrome profile; rc 2 when none is set, 3 when open failed
  local _prof
  _prof=$(chrome_profile_of "$1") || return 2
  open -na "Google Chrome" --args --profile-directory="$_prof" && return 0
  note "could not open Chrome profile '$_prof'"
  return 3
}

# ── subcommands ─────────────────────────────────────────────────────────────────────────────
cmd_whoami() {
  local e; e=$(live_email)
  [ -n "$e" ] || die 2 "$(no_account_why)"
  printf '%s\n' "$e"
}

park_as() {  # $1 email, $2 its oauthAccount JSON, a full credential JSON on STDIN: park both in the slot
  local _slot _prev _had=0
  valid_email "$1" || die 2 "refusing to name a slot after '$1' — not a plain email address"
  same_email "$(email_of "$2")" "$1" \
    || die 2 "refusing to park $1 under an identity record that names '$(email_of "$2")'"
  _slot=$(jq -c --argjson a "$2" \
    'select(type == "object" and (.claudeAiOauth | type) == "object") | {claudeAiOauth, oauthAccount: $a}' 2>/dev/null)
  [ -n "$_slot" ] || die 2 "the live item carries no claudeAiOauth account token — log in first"
  _prev=$(kc_read "$SLOT_PREFIX$1") && _had=1
  printf '%s' "$_slot" | kc_write "$SLOT_PREFIX$1" && return 0
  # The write attempt may have landed damaged: put the slot back as it was, so exit 2 keeps
  # meaning "nothing changed", and say so when even that is not possible.
  if [ "$_had" -eq 1 ]; then
    printf '%s' "$_prev" | kc_write "$SLOT_PREFIX$1" \
      && die 2 "could not write slot $SLOT_PREFIX$1; its previous value is intact"
  else
    security delete-generic-password -s "$SLOT_PREFIX$1" -a "$KC_ACCOUNT" >/dev/null 2>&1
    kc_read "$SLOT_PREFIX$1" >/dev/null \
      || die 2 "could not write slot $SLOT_PREFIX$1; no slot was left behind"
  fi
  die 2 "could not write slot $SLOT_PREFIX$1 AND could not put it back — re-run: claude-acct.sh save"
}
read_live_as() {  # $1 email → LIVE_CRED and LIVE_ACCT, both proven to belong to $1
  # Sets two globals, so call it directly, never in $(...). The label comes from `claude auth
  # status`, the bytes from the keychain and .claude.json: three reads. The identity must name
  # $1, and the account is confirmed again AFTER both reads, so a login or refresh landing in
  # between cannot file one account's records under another's name.
  LIVE_CRED=$(kc_read "$LIVE_SERVICE") || die 2 "no live credential item ($LIVE_SERVICE, -a $KC_ACCOUNT)"
  LIVE_ACCT=$(live_account) \
    || die 2 "$CCJ carries no readable oauthAccount — sign in first: claude auth login"
  same_email "$(email_of "$LIVE_ACCT")" "$1" \
    || die 2 "the identity in $CCJ ($(email_of "$LIVE_ACCT")) is not $1, the account claude reports — retry"
  [ "$(confirmed_email)" = "$1" ] || die 2 "the live account changed while it was being read — retry"
}
save_live_as() {  # $1 email: park the live token and identity in that email's slot
  read_live_as "$1"
  # park_as is the last stage of a pipeline, so it runs in a subshell and its `die` exits only
  # that subshell. Propagate the status, or a refused park would print "saved" and exit 0.
  printf '%s' "$LIVE_CRED" | park_as "$1" "$LIVE_ACCT" || exit $?
}

# One save/add/use at a time: two panes running `use` at once would each park and write the live
# records. The lock is a symlink whose TARGET is the owner pid: `ln -s` creates it and publishes
# the pid in one atomic step, so no reader ever sees a lock without an owner. A dead owner's lock
# is removed only by the holder of "<lock>.break", after re-reading it under that lock (the
# standard lock-breaker pattern): two runs that saw the same dead pid can never remove a
# lock a live run took in between.
LOCK="$STATE_DIR/lock"
HELD_LOCK=0
HELD_CCJ_LOCK=""
SHIM_DIR=""
cleanup() {
  [ "$HELD_LOCK" -eq 1 ] && [ "$(readlink "$LOCK" 2>/dev/null)" = "$$" ] && rm -f "$LOCK"
  [ -n "$HELD_CCJ_LOCK" ] && rmdir "$HELD_CCJ_LOCK" 2>/dev/null   # a signal mid-write never strands Claude Code's lock
  [ -n "$SHIM_DIR" ] && rm -r "$SHIM_DIR" 2>/dev/null
  return 0
}
trap cleanup EXIT
take_lock() {
  { mkdir -p "$STATE_DIR" 2>/dev/null && chmod 700 "$STATE_DIR" 2>/dev/null; } || die 2 "cannot create $STATE_DIR"
  local _try _pid
  for _try in 1 2 3; do
    # A pre-identity lock is a DIRECTORY holding a pid file. Test for it before `ln -s`, which
    # given an existing directory puts the link inside it and succeeds without locking anything.
    if [ -d "$LOCK" ] && [ ! -L "$LOCK" ]; then
      _pid=$(cat "$LOCK/pid" 2>/dev/null)
      if [ -n "$_pid" ] && kill -0 "$_pid" 2>/dev/null; then
        die 2 "another claude-acct run holds the lock (pid $_pid)"
      fi
      # Same breaker as below: another run may have removed this directory and taken the
      # symlink lock since the read above, so re-check the type and the pid under it.
      if mkdir "$LOCK.break" 2>/dev/null; then
        if [ -d "$LOCK" ] && [ ! -L "$LOCK" ] && [ "$(cat "$LOCK/pid" 2>/dev/null)" = "$_pid" ]; then
          rm -r "$LOCK" 2>/dev/null
        fi
        rmdir "$LOCK.break" 2>/dev/null
      fi
      continue
    fi
    [ "$_try" -gt 1 ] && sleep 0.2   # a contended .break is usually released within moments
    if ln -s "$$" "$LOCK" 2>/dev/null; then HELD_LOCK=1; return 0; fi
    _pid=$(readlink "$LOCK" 2>/dev/null) || _pid=""
    if [ -n "$_pid" ] && kill -0 "$_pid" 2>/dev/null; then
      die 2 "another claude-acct run holds the lock (pid $_pid)"
    fi
    if mkdir "$LOCK.break" 2>/dev/null; then
      [ "$(readlink "$LOCK" 2>/dev/null)" = "$_pid" ] && rm -f "$LOCK"
      rmdir "$LOCK.break" 2>/dev/null
    fi
  done
  die 2 "could not take $LOCK (if no claude-acct run is active, remove it and $LOCK.break)"
}

cmd_save() {
  take_lock
  local e; e=$(live_email)
  [ -n "$e" ] || die 2 "$(no_account_why)"
  save_live_as "$e"
  printf 'saved %s\n' "$e"
}

cmd_add() {
  [ $# -eq 1 ] || die 1 "usage: claude-acct.sh add <email>"
  valid_email "$1" || die 1 "add takes a plain email address: $1"
  take_lock
  local cur; cur=$(live_email)
  if [ -n "$cur" ]; then save_live_as "$cur"; note "saved the current account ($cur) first"
  else
    # Logging in replaces the live token. Proceed unparked only when there is no account token to
    # lose: a live claude.ai token whose account could not be named would be overwritten with no
    # slot to come back to, and a CLI that could not be asked says nothing either way.
    local _st; _st=$(live_state)
    case "$_st" in
      out) ;;
      "noemail "*) ! live_has_account_token \
                     || die 2 "$(no_account_why "$_st") — refusing to log in over a live token that could not be saved first" ;;
      *) die 2 "$(no_account_why "$_st") — refusing to log in over a live token that could not be saved first" ;;
    esac
  fi
  # The sign-in page must open in THIS account's Chrome profile: in whichever window is
  # frontmost, an approval twice went to the wrong account. Claude Code opens its login URL by
  # exec'ing $BROWSER with the URL as its one argument (CLI 2.1.312 binary, measured), so
  # $BROWSER names a shim that opens that URL in the profile.
  local prof="" shim=""
  if prof=$(chrome_profile_of "$1"); then
    if SHIM_DIR=$(mktemp -d "$STATE_DIR/browser.XXXXXX" 2>/dev/null); then
      shim="$SHIM_DIR/open-in-profile"
      # shellcheck disable=SC2016  # the shim expands these when it runs, not now
      printf '#!/bin/bash\nexec open -na "Google Chrome" --args --profile-directory="$CLAUDE_ACCT_CHROME_PROFILE" "$1"\n' \
        > "$shim" && chmod 700 "$shim" || shim=""
    fi
    [ -n "$shim" ] || note "could not create the browser shim — the sign-in page opens in the default browser"
  else
    note "no Chrome profile set for $1 in $CONF (third column) — the sign-in page opens in the frontmost browser window"
  fi
  if [ -n "$shim" ]; then
    note ">>> sign in as $1 in Chrome profile \"$prof\" — if the page opens anywhere else, paste the link claude prints into that profile <<<"
    BROWSER="$shim" CLAUDE_ACCT_CHROME_PROFILE="$prof" claude auth login --email "$1" \
      || die 2 "claude auth login did not complete"
  else
    note ">>> sign in as $1 — make sure the browser window that opens is $1's <<<"
    claude auth login --email "$1" || die 2 "claude auth login did not complete"
  fi
  local now; now=$(live_email)
  same_email "$now" "$1" || die 2 "after login the live account is '${now:-none}', not $1 — nothing saved"
  save_live_as "$1"
  # Re-adding the account that was already live (to give its slot an identity) is not a switch:
  # no log row, and no "switch back" hint that names the account you are on.
  if same_email "${cur:-}" "$1"; then
    printf 'added %s (it was already live; its slot is refreshed)\n' "$1"
    return 0
  fi
  record_switch "${cur:-}" "$1"
  printf 'added %s (live now)%s\n' "$1" "${cur:+; switch back with: claude-acct.sh use $cur}"
}

record_switch() {  # $1 from, $2 to
  same_email "$1" "$2" && return 0   # staying on one account is not a switch
  if ! { mkdir -p "$STATE_DIR" 2>/dev/null && chmod 700 "$STATE_DIR" 2>/dev/null; } \
     || ! jq -cn --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg from "$1" --arg to "$2" \
          '{ts: $ts, from: $from, to: $to}' >> "$SWITCHES" 2>/dev/null; then
    note "could not record the switch in $SWITCHES — \`usage\` will misattribute from here"
    return 0
  fi
  chmod 600 "$SWITCHES" 2>/dev/null || true   # which accounts exist and when: not world-readable
}

cmd_use() {
  local target="" chrome=1 expect="" have_expect=0 not_after="" have_not_after=0
  local usage="usage: claude-acct.sh use <alias|email> [--no-chrome] [--expect-from <email>] [--not-after <epoch-seconds>]"
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --no-chrome) chrome=0; shift ;;
      --expect-from)
        [ "$have_expect" -eq 0 ] || die 1 "--expect-from given twice"
        [ "$#" -ge 2 ] || die 1 "$usage"
        expect="$2"; have_expect=1; shift 2 ;;
      --not-after)
        [ "$have_not_after" -eq 0 ] || die 1 "--not-after given twice"
        [ "$#" -ge 2 ] || die 1 "$usage"
        # Digits only, no leading zero (invalid octal to $(( ))), at most 15 of them (inside 64-bit arithmetic).
        case "$2" in ''|*[!0-9]*|0?*) die 1 "--not-after needs an epoch-seconds integer, got '$2'" ;; esac
        [ "${#2}" -le 15 ] || die 1 "--not-after needs an epoch-seconds integer, got '$2'"
        not_after="$2"; have_not_after=1; shift 2 ;;
      -*) die 1 "unknown flag: $1" ;;
      *) [ -z "$target" ] || die 1 "use takes one account"; target="$1"; shift ;;
    esac
  done
  [ -n "$target" ] || die 1 "$usage"
  if [ "$have_expect" -eq 1 ]; then
    valid_email "$expect" || die 1 "--expect-from needs a plain email address, got '$expect'"
  fi
  local email; email=$(resolve_email "$target") \
    || die 1 "'$target' is neither a plain email address nor an alias in $CONF"

  take_lock
  # Under the lock, before anything is read: a run that took the lock by the named second may go on
  # (and holds the lock while it does), one that took it later switches nothing.
  if [ "$have_not_after" -eq 1 ]; then
    local _now; _now=$(date +%s)
    case "$_now" in ''|*[!0-9]*) die 2 "could not read the clock for --not-after; nothing was switched" ;; esac
    [ "$_now" -gt "$not_after" ] && die 2 "past --not-after $not_after; nothing was switched"
  fi
  local cur; cur=$(live_email)
  [ -n "$cur" ] || die 2 "$(no_account_why) — cannot tell which slot the live token belongs to"
  # Read under the lock, so a switch planned against an earlier view stops instead of swapping
  # an account nobody chose.
  if [ "$have_expect" -eq 1 ] && ! same_email "$cur" "$expect"; then
    die 2 "the live account is $cur, not $expect (--expect-from); nothing was switched"
  fi
  if [ "$cur" = "$email" ]; then
    note "already on $email"
  else
    local _raw _tok _acct _bad
    _raw=$(kc_read "$SLOT_PREFIX$email") \
      || die 2 "no saved token for $email — run: claude-acct.sh add $email"
    # The identity is never guessed: the token carries none, so a slot without its record
    # (one saved before identity slots) cannot be switched to. One sign-in rebuilds it.
    _bad=$(slot_problem "$_raw" "$email")
    [ -z "$_bad" ] || die 2 "slot $SLOT_PREFIX$email: $_bad — re-run: claude-acct.sh add $email"
    _tok=$(printf '%s' "$_raw" | part_of claudeAiOauth)
    _acct=$(printf '%s' "$_raw" | part_of oauthAccount)

    read_live_as "$cur"
    local _orig="$LIVE_CRED" _orig_acct="$LIVE_ACCT" _new
    # Compose before parking, so every exit 2 below this point still means "nothing changed".
    _new=$(printf '%s\n%s\n' "$_orig" "$_tok" | jq -cs '.[0] + {claudeAiOauth: .[1]}') \
      || die 2 "could not compose the new credential"
    # Park the CURRENT records (the token may have refreshed since last saved) from the same
    # reads that _new and any restore are built from, so parked, written, and restored agree.
    printf '%s' "$_orig" | park_as "$cur" "$_orig_acct" || exit $?   # a failed park must stop the switch
    # Re-read just before the write: a running session that refreshed the login since read_live_as
    # would otherwise have its new token overwritten. Narrows the race; cannot close it (RESIDUAL).
    local _pre; _pre=$(kc_read "$LIVE_SERVICE") || _pre=""
    if [ "$(printf '%s' "$_pre" | shasum -a 256)" != "$(printf '%s' "$_orig" | shasum -a 256)" ]; then
      die 2 "the live login changed during the switch (a running session refreshed it); nothing was switched — run it again"
    fi
    if ! printf '%s' "$_new" | kc_write "$LIVE_SERVICE"; then
      # The read-back did not match. Classify what is live, once, and never write over a token
      # this run did not write.
      local _class
      live_read \
        || die 4 "switch to $email failed AND restoring $cur failed (the live login could not be read back, so nothing was rewritten) — run: claude auth login --email $cur"
      _class=$(live_class "$LIVE_BYTES" "$_new" "$_orig")
      case "$_class" in
        new) ;;   # the token landed; only another key changed (an MCP refresh): go on
        orig) die 3 "switch to $email failed; nothing changed ($cur is still live)" ;;
        foreign) die 4 "$(foreign_msg "$cur")" ;;
        *) if printf '%s' "$_orig" | kc_write "$LIVE_SERVICE"; then
             die 3 "switch to $email failed; the original token and identity are restored ($cur)"
           fi
           die 4 "switch to $email failed AND restoring $cur failed — run: claude auth login --email $cur" ;;
      esac
    fi
    if ! ccj_set_account "$_acct" || ! same_email "$(confirmed_email)" "$email"; then
      local _rb=0
      restore_both "$_orig" "$_orig_acct" "$_new" || _rb=$?
      case "$_rb" in
        0) die 3 "switch to $email failed; the original token and identity are restored ($cur)" ;;
        5) die 4 "$(foreign_msg "$cur")" ;;
      esac
      die 4 "switch to $email failed AND restoring $cur failed — run: claude auth login --email $cur"
    fi
    record_switch "$cur" "$email"
    printf 'switched %s -> %s\n' "$cur" "$email"
    note "new sessions start on $email; running sessions move at their next request (if one does not: /exit, then claude --continue)"
    [ -e "$CCD/.credentials.json" ] \
      && note "$CCD/.credentials.json exists — running sessions read it instead of the keychain; move it aside"
  fi

  if [ "$chrome" -eq 1 ]; then
    # A Chrome problem never fails a switch that landed: a missing profile is a note, and a
    # failed open already printed its own.
    open_chrome_for "$email"
    [ "$?" -eq 2 ] && note "no Chrome profile set for $email in $CONF (third column) — skipped"
  fi
  return 0
}

cmd_where() {  # the two values that pick the credential store, then the state dir; reads no credential
  [ "$#" -eq 0 ] || die 1 "usage: claude-acct.sh where"
  printf 'config_dir=%s\nkeychain_account=%s\nstate_dir=%s\n' "$CCD" "$KC_ACCOUNT" "$STATE_DIR"
}

cmd_chrome() {
  [ "$#" -eq 1 ] || die 1 "usage: claude-acct.sh chrome <alias|email>"
  local email; email=$(resolve_email "$1") \
    || die 1 "'$1' is neither a plain email address nor an alias in $CONF"
  open_chrome_for "$email"
  case "$?" in
    0) ;;
    2) die 2 "no Chrome profile set for $email in $CONF (third column)" ;;
    *) die 3 "could not open the Chrome profile for $email" ;;
  esac
}

# Every account this machine knows, once each: the accounts file, the switch log, the live one ($1).
known_emails() {
  local emails=""
  if [ -r "$CONF" ]; then emails=$(awk -F'\t' 'NF >= 2 && $1 !~ /^#/ { print $2 }' "$CONF"); fi
  if [ -r "$SWITCHES" ]; then
    emails=$(printf '%s\n%s\n' "$emails" "$(jq -r '.from, .to' "$SWITCHES" 2>/dev/null)")
  fi
  [ -n "${1:-}" ] && emails=$(printf '%s\n%s\n' "$emails" "$1")
  printf '%s\n' "$emails" | awk 'NF && !seen[$0]++'
}

cmd_list() {
  local json=0
  case "$#:${1:-}" in
    0:) ;;
    1:--json) json=1 ;;
    *) die 1 "usage: claude-acct.sh list [--json]" ;;
  esac
  # A caller reads the JSON array as the whole fleet, so a source of the account list that
  # exists but cannot be read refuses the list instead of silently shortening it.
  if [ "$json" -eq 1 ]; then
    if { [ -e "$CONF" ] && [ ! -r "$CONF" ]; } \
       || { [ -e "$SWITCHES" ] && ! jq empty "$SWITCHES" >/dev/null 2>&1; }; then
      note "list --json: the accounts file or switch log cannot be read; nothing printed"
      exit 2
    fi
  fi
  local cur; cur=$(live_email)
  if [ -z "$cur" ]; then
    local _st; _st=$(live_state)
    [ "$_st" = out ] || note "$(no_account_why "$_st") — no account is marked live below"
  fi
  local e
  local now; now=$(date +%s)
  known_emails "$cur" | { while IFS= read -r e; do
    local mark=" " saved="no saved token" raw="" bad="" exp="" days="" expiry="" until=""
    local is_saved=false
    [ "$e" = "$cur" ] && mark="*"
    if raw=$(kc_read "$SLOT_PREFIX$e"); then
      saved="saved"; is_saved=true
      bad=$(slot_problem "$raw" "$e")
      [ -z "$bad" ] || saved="saved, $bad — re-run: claude-acct.sh add $e"
      # refreshTokenExpiresAt is epoch milliseconds; past it, the slot cannot sign in at all.
      exp=$(printf '%s' "$raw" | jq -r '.claudeAiOauth.refreshTokenExpiresAt // empty | numbers | . / 1000 | floor' 2>/dev/null)
      # Only whole seconds reach shell arithmetic: jq prints a huge value as 1e+30, and `$(( ))`
      # on that kills the loop. A corrupt expiry makes the slot unusable, not the list short.
      case "$exp" in
        ''|*[!0-9]*)
          if [ -n "$exp" ]; then
            exp=""; [ -n "$bad" ] || bad="unreadable refresh-token expiry"
            saved="saved, $bad — re-run: claude-acct.sh add $e"
          fi ;;
      esac
      if [ -n "$exp" ]; then
        days=$(( (exp - now) / 86400 ))
        until=$(date -r "$exp" +%Y-%m-%d)
        expiry="; refresh token until $until"
        if [ "$exp" -le "$now" ]; then expiry="$expiry — EXPIRED, re-run: claude-acct.sh add $e"
        elif [ "$days" -le 7 ]; then expiry="$expiry — EXPIRES IN ${days}d, re-run: claude-acct.sh add $e"
        fi
      else
        expiry="; refresh-token expiry unknown"
      fi
    fi
    if [ "$json" -eq 0 ]; then
      printf '%s %-40s %s%s\n' "$mark" "$e" "$saved" "$expiry"
      continue
    fi
    # Non-secret fields only: nothing from the slot but its expiry and its problem text. A row
    # that cannot be rendered prints a non-JSON marker, which makes the closing jq -s fail:
    # a caller must never read a short array as the whole fleet.
    jq -nc --arg email "$e" --arg alias "$(alias_of "$e" 2>/dev/null)" \
      --argjson live "$([ "$mark" = "*" ] && echo true || echo false)" \
      --argjson saved "$is_saved" \
      --argjson slot_ok "$([ "$is_saved" = true ] && [ -z "$bad" ] && echo true || echo false)" \
      --arg slot_problem "$bad" --arg until "$until" --arg exp "$exp" --arg days "$days" --argjson now "$now" \
      --arg chrome "$(chrome_profile_of "$e" 2>/dev/null)" \
      --argjson last_resort "$(last_resort_of "$e" && echo true || echo false)" \
      '{email: $email, alias: (if $alias == "" then null else $alias end), live: $live, saved: $saved,
        slot_ok: $slot_ok, slot_problem: (if $slot_problem == "" then null else $slot_problem end),
        refresh_until: (if $until == "" then null else $until end),
        refresh_expired: (if $exp == "" then false else (($exp | tonumber) <= $now) end),
        refresh_expires_in_days: (if $days == "" then null else ($days | tonumber) end),
        chrome_profile: (if $chrome == "" then null else $chrome end), last_resort: $last_resort}' \
      || printf 'row-failed %s\n' "$e"
  done
  # The loop runs in a pipeline subshell. In JSON mode it closes with a completeness record, so a
  # loop that died partway (no record) is refused too, not printed as a shorter list. The record
  # is printed by that same subshell, after the loop: a subshell killed mid-loop prints none.
  [ "$json" -eq 1 ] && printf '{"__list_complete":true}\n'
  } | if [ "$json" -eq 1 ]; then
      jq -cs 'if length > 0 and (.[-1] | type) == "object" and .[-1].__list_complete == true
              then .[:-1] else error("incomplete") end' 2>/dev/null \
        || { note "list --json: an account could not be rendered; nothing printed"; exit 2; }
    else cat; fi
}

# 7-day quota per known account, from the newest reading `record-limits` kept for it:
# ~/.cache/claude-limits/latest/<email>.json. No network and no secret: an account no session on
# this machine has used since recording began has no reading, and says so rather than printing 0%.
cmd_limits() {
  [ $# -eq 0 ] || die 1 "limits takes no arguments"
  local dir="${CLAUDE_ACCT_LIMITS_DIR:-$HOME/.cache/claude-limits}/latest" cur
  cur=$(live_email)
  # A table of quota LEFT that fits a narrow pane: a row is
  # "{mark} {email:<W} {left:>4}  {resets}", 22 + W columns when RESETS is its longest
  # (13, "Wed 11 12:00a"), so 46 with today's longest email (24). Zone, staleness, and 5-hour
  # readings go on footer lines wrapped at 46, never on rows.
  known_emails "$cur" | python3 -I -c '
import datetime as dt, json, math, os, sys, textwrap, time
d, cur = sys.argv[1], sys.argv[2]
now = time.time()
WIDTH = 46
def local(t):
    return dt.datetime.fromtimestamp(t).astimezone()
def ap(t):
    return local(t).strftime("%p")[0].lower()
zones = []           # every zone a printed time is in, so a DST change shows both
def shown(t, fmt):
    z = local(t).strftime("%Z")
    if z not in zones:
        zones.append(z)
    return local(t).strftime(fmt) + ap(t)
def resets(t):        # "Mon 9 6:00a"
    return shown(t, "%a %-d %-I:%M")
def was(t):           # "was 9 6:00a": no weekday, so an expired row is no wider than a live one
    return "was " + shown(t, "%-d %-I:%M")
def age(s):
    s = max(0, int(s))
    if s < 90: return f"{s}s"
    if s < 5400: return f"{s // 60}m"
    if s < 172800: return f"{s // 3600}h"
    return f"{s // 86400}d"
def stamp(iso):
    return dt.datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()
def wrapped(text):
    return textwrap.wrap(text, width=WIDTH, subsequent_indent="  ", break_on_hyphens=False, break_long_words=False)
def packed(prefix, items):
    # Whole "email value" items per line, so a line break never splits an email from its value.
    lines, cur = [], prefix
    for i, it in enumerate(items):
        piece = it + ("," if i < len(items) - 1 else "")
        if cur.strip() and len(cur) + 1 + len(piece) > WIDTH and cur not in (prefix, "  "):
            lines.append(cur)
            cur = "  " + piece
        else:
            cur = (cur + " " + piece) if cur.strip() and not cur.endswith(" ") else cur + piece
    lines.append(cur)
    return lines
emails = [l.strip() for l in sys.stdin if l.strip()]
if not emails:
    print("\n".join(wrapped("no accounts known yet (none in the accounts file, the switch log, or live)")))
    sys.exit(0)
head = "ACCOUNT"
w = max(len(head), max(len(e) for e in emails))
print(f"  {head:<{w}} LEFT  RESETS")
def num(r, k):
    # A field that is absent or null is None; one present but not a finite number is a bad file.
    v = r.get(k)
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
        raise ValueError(k)
    return v
def left_of(p):
    return f"{min(100, max(0, round(100 - p)))}%"
stale, five, bad = [], [], []
for e in emails:
    mark = "*" if e == cur else " "
    try:
        try:
            r = json.load(open(os.path.join(d, e + ".json")))
        except OSError:
            r = {}
        if not isinstance(r, dict):
            raise ValueError("not an object")
        pct, reset = num(r, "seven_day_pct"), num(r, "seven_day_resets_at")
        fh, fr = num(r, "five_hour_pct"), num(r, "five_hour_resets_at")
        if pct is None:
            left, when = "-", "no reading"
        elif reset and reset > now:
            left, when = left_of(pct), resets(reset)
        elif reset:
            left, when = "-", was(reset)
        else:
            left, when = left_of(pct), "unknown"
        # A reading with an unreadable capture time is listed as stale with age "?", never as fresh.
        if r:
            try:
                old = now - stamp(r["captured_at"])
                got = age(old) if old > 3600 else None
            except (KeyError, ValueError, TypeError, AttributeError, OverflowError, OSError):
                got = "?"
            if got:
                stale.append(f"{e} {got}")
        if fh is not None and fr and fr > now:
            five.append(f"{e} {fh:g}%")
    except (ValueError, TypeError, OverflowError, OSError):
        # One malformed file costs its own row, never the rest of the table.
        left, when = "-", "unreadable"
        bad.append(e)
    print(f"{mark} {e:<{w}} {left:>4}  {when}")
print("7-day quota · times " + "/".join(zones or [local(now).strftime("%Z")]))
# the 2.1.319 statusline rate_limits carries only five_hour, seven_day, and spend_limit.
print("\n".join(wrapped("Per-model weekly caps (Fable) are not in the statusline payload, so a session can hit one before these numbers say so.")))
if five:
    print("\n".join(packed("5h: ", five)))
if stale:
    print("\n".join(packed("stale (>1h): ", stale)))
if bad:
    print("\n".join(packed("unreadable reading: ", bad)))
' "$dir" "$cur"
}

# Record one statusline payload's quota reading (stdin: the JSON Claude Code hands a statusline
# command) as the newest reading for the account it was made on. Pipe the payload through it from
# your statusline script; it prints nothing and always exits 0, so it can never break the line.
# Claude Code's payload carries no account field, so the account comes from two sources:
#   1. Each account has its own 7-day reset time, computed server-side from the token the request
#      was sent with. A reading whose reset time equals the latest reading of exactly ONE other
#      known account is that account's: a session that had not yet followed a switch.
#   2. Otherwise the live account in .claude.json (parsed only when that file changes).
# A session started with CLAUDE_CODE_OAUTH_TOKEN runs on that token's account, which .claude.json
# never names, so rule 2 would file its reading under whoever is live. For such a session rule 1
# alone decides, over every known account including the live one; no match, or no 7-day reset
# time, and the reading is dropped. Claude Code removes that variable from the statusline
# command's own environment (2.1.319), so token_session looks for it in the environment of each
# process from our parent up to the first `claude` process (`ps -E` on macOS, /proc elsewhere),
# counting matches only: the value is never printed or kept.
# Within one reset window the used percent never goes down, so a lower figure there is a stale or
# out-of-order reading: when the stored reading's 7-day reset equals this one's and its percent is
# higher, the stored percent stays. The 5-hour pair, keyed on its own reset, likewise.
# A reading with no 5-hour figure (Ultra plans dropped that window) is kept as is; `limits` shows
# only the windows a reading has. A reading with no 7-day figure is not kept.
token_session() {
  [ -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ] && return 0
  local p="$PPID" i=0 n c
  while [ "$i" -lt 8 ]; do
    case "$p" in ''|0|1|*[!0-9]*) return 1 ;; esac
    if [ -r "/proc/$p/environ" ]; then
      n=$(tr '\0' '\n' 2>/dev/null < "/proc/$p/environ" | grep -c '^CLAUDE_CODE_OAUTH_TOKEN=.')
    else
      n=$(ps -E -ww -o command= -p "$p" 2>/dev/null | grep -c ' CLAUDE_CODE_OAUTH_TOKEN=[^ ]')
    fi
    [ "${n:-0}" -gt 0 ] 2>/dev/null && return 0
    c=$(ps -o comm= -p "$p" 2>/dev/null)
    case "${c##*/}" in claude) return 1 ;; esac
    case "$c" in */claude/versions/*) return 1 ;; esac
    p=$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' ')
    i=$((i + 1))
  done
  return 1
}

cmd_record_limits() {
  local base="${CLAUDE_ACCT_LIMITS_DIR:-$HOME/.cache/claude-limits}" input line email reset idc tok=0 merged
  input=$(cat) || return 0
  case "$input" in *'"rate_limits"'*) : ;; *) return 0 ;; esac
  ( umask 077; mkdir -p "$base/latest" ) 2>/dev/null || return 0
  idc="$base/identity.json"
  if [ -s "$CCJ" ] && { [ ! -s "$idc" ] || [ "$CCJ" -nt "$idc" ]; }; then
    ( umask 077; jq -r '.oauthAccount.emailAddress // ""' "$CCJ" > "$idc.$$" 2>/dev/null \
        && mv -f "$idc.$$" "$idc" || rm -f "$idc.$$" ) 2>/dev/null
  fi
  email=$(cat "$idc" 2>/dev/null)
  reset=$(printf '%s' "$input" | jq -r '.rate_limits.seven_day.resets_at // empty' 2>/dev/null)
  token_session && tok=1
  case "$reset" in
    ''|*[!0-9]*) [ "$tok" = 1 ] && return 0 ;;
    *)
      if [ "$tok" = 1 ]; then
        email=$(find "$base/latest" -maxdepth 1 -name '*@*.json' -exec cat {} + 2>/dev/null \
          | jq -r -s --argjson r "$reset" '
              [.[] | select(.seven_day_resets_at == $r) | .email // ""] | unique
              | if length == 1 and .[0] != "" then .[0] else empty end' 2>/dev/null)
        [ -n "$email" ] || return 0
      elif [ "$(jq -r '.seven_day_resets_at // empty' "$base/latest/$email.json" 2>/dev/null)" != "$reset" ]; then
        local other
        other=$(find "$base/latest" -maxdepth 1 -name '*@*.json' -exec cat {} + 2>/dev/null \
          | jq -r -s --argjson r "$reset" --arg live "$email" '
              [.[] | select(.seven_day_resets_at == $r) | .email // ""] | unique
              | if length == 1 and .[0] != $live and .[0] != "" then .[0] else empty end' 2>/dev/null)
        [ -n "$other" ] && email="$other"
      fi
      ;;
  esac
  case "$email" in ''|*[!A-Za-z0-9._%+@-]*|*@*@*) return 0 ;; *@*) : ;; *) return 0 ;; esac
  line=$(printf '%s' "$input" | jq -c --arg e "$email" --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{
      captured_at: $ts, email: $e, cc_version: (.version // null),
      five_hour_pct:       (.rate_limits.five_hour.used_percentage // null),
      five_hour_resets_at: (.rate_limits.five_hour.resets_at       // null),
      seven_day_pct:       (.rate_limits.seven_day.used_percentage // null),
      seven_day_resets_at: (.rate_limits.seven_day.resets_at       // null)}' 2>/dev/null)
  case "$line" in ''|*'"seven_day_pct":null'*) return 0 ;; esac
  # Read, merge, and rename under a per-account mkdir lock, so two sessions on one account
  # recording at once cannot both merge against the same stored value and lose the higher one.
  # A held lock skips this write (the holder has an equally fresh reading); one older than a
  # minute belongs to a crashed writer.
  local lock="$base/latest/.$email.lock"
  # A writer that clears a stale lock skips its own write, so two that both saw it stale never
  # both write; the next reading takes the lock normally. Left open: a writer that saw the lock
  # stale can remove a fresh one taken in the instant after another writer cleared it, which needs
  # a crashed holder and three writers in that instant, and costs at most one reading.
  if ! mkdir "$lock" 2>/dev/null; then
    [ -n "$(find "$lock" -maxdepth 0 -mmin +1 2>/dev/null)" ] && rmdir "$lock" 2>/dev/null
    return 0
  fi
  if [ -s "$base/latest/$email.json" ]; then
    merged=$(jq -c --argjson n "$line" '
        . as $o | $n
        | if $o.seven_day_resets_at != null and $o.seven_day_resets_at == $n.seven_day_resets_at
             and ($o.seven_day_pct | type) == "number" and $o.seven_day_pct > $n.seven_day_pct
          then .seven_day_pct = $o.seven_day_pct else . end
        | if $o.five_hour_resets_at != null and $o.five_hour_resets_at == $n.five_hour_resets_at
             and ($o.five_hour_pct | type) == "number" and ($n.five_hour_pct | type) == "number"
             and $o.five_hour_pct > $n.five_hour_pct
          then .five_hour_pct = $o.five_hour_pct else . end' "$base/latest/$email.json" 2>/dev/null)
    [ -n "$merged" ] && line="$merged"
  fi
  ( umask 077
    [ -e "$base/latest/.since" ] || date -u +%Y-%m-%dT%H:%M:%SZ > "$base/latest/.since"
    printf '%s\n' "$line" > "$base/latest/.$email.$$" \
      && mv -f "$base/latest/.$email.$$" "$base/latest/$email.json" \
      || rm -f "$base/latest/.$email.$$" ) 2>/dev/null
  rmdir "$lock" 2>/dev/null
  return 0
}

cmd_usage() {
  local days=7
  while [ $# -gt 0 ]; do
    case "$1" in
      --days) days="${2:-}"; shift 2 || die 1 "--days needs a number" ;;
      *) die 1 "unknown argument: $1" ;;
    esac
  done
  case "$days" in ''|*[!0-9]*) die 1 "--days needs a whole number" ;; esac
  python3 - "$CCD/projects" "$SWITCHES" "$days" "$(live_email)" <<'PY'
import json, os, sys, glob, datetime as dt
proj, switches, days, live = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
now = dt.datetime.now(dt.timezone.utc)
since = now - dt.timedelta(days=days)
def ts(s):
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
sw = []
if os.path.exists(switches):
    for line in open(switches):
        try:
            r = json.loads(line); sw.append((ts(r["ts"]), r.get("from") or "", r["to"]))
        except Exception:
            pass
sw.sort()
def account_at(t):
    # Before the first recorded switch, the live account is that switch's FROM; with no
    # switches at all, it is whoever is live now. Neither is a guess about a switch nobody logged.
    if not sw:
        return live or "(unknown)"
    acct = sw[0][1] or "(before first switch)"
    for when, _frm, to in sw:
        if when <= t:
            acct = to
        else:
            break
    return acct
seen, tot = set(), {}
# Recursive: subagent transcripts sit a level deeper (<project>/<session>/subagents/*.jsonl) and
# bill to the same account. Dedup by message id below absorbs any record seen twice.
for f in glob.glob(os.path.join(proj, "**", "*.jsonl"), recursive=True):
    try:
        if dt.datetime.fromtimestamp(os.path.getmtime(f), dt.timezone.utc) < since:
            continue
        fh = open(f)
    except OSError:
        continue
    for line in fh:
        if '"usage"' not in line:
            continue
        try:
            r = json.loads(line)
            m = r["message"]; u = m["usage"]; mid = m["id"]; t = ts(r["timestamp"])
        except Exception:
            continue
        if mid in seen or t < since:
            continue
        seen.add(mid)
        a = tot.setdefault(account_at(t), [0, 0, 0, 0, 0])
        a[0] += 1
        a[1] += u.get("input_tokens") or 0
        a[2] += u.get("output_tokens") or 0
        a[3] += u.get("cache_creation_input_tokens") or 0
        a[4] += u.get("cache_read_input_tokens") or 0
print(f"Token usage by account, last {days}d (transcripts under {proj}; {len(sw)} recorded switch(es))")
print(f"{'account':40} {'msgs':>7} {'input':>10} {'output':>10} {'cache-write':>12} {'cache-read':>13}")
for k in sorted(tot, key=lambda k: -tot[k][2]):
    v = tot[k]
    print(f"{k:40} {v[0]:>7} {v[1]:>10} {v[2]:>10} {v[3]:>12} {v[4]:>13}")
if not tot:
    print("(no usage records in the window)")
print("Plan limits and reset times are per account on claude.ai/settings/usage; /usage in a pane shows the live one.")
PY
}

# ── dispatch ────────────────────────────────────────────────────────────────────────────────
[ $# -ge 1 ] || { usage_text; exit 1; }
sub="$1"; shift
case "$sub" in
  -h|--help|help|'?') usage_text; exit 0 ;;
  whoami) cmd_whoami ;;
  save)   cmd_save ;;
  add)    cmd_add "$@" ;;
  use)    cmd_use "$@" ;;
  list)   cmd_list "$@" ;;
  where)  cmd_where "$@" ;;
  chrome) cmd_chrome "$@" ;;
  limits) cmd_limits "$@" ;;
  record-limits) cmd_record_limits; exit 0 ;;
  usage)  cmd_usage "$@" ;;
  *) die 1 "unknown subcommand: $sub (try --help)" ;;
esac
