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
#
# Usage:
#   claude-acct.sh whoami                 the account Claude Code reports (via `claude auth status`)
#   claude-acct.sh save                   park the live token + identity in its slot (run after a login)
#   claude-acct.sh add <email>            save the current account, sign in as <email> in its Chrome
#                                         profile (`claude auth login`, via $BROWSER), save it
#   claude-acct.sh use <alias|email>      switch; opens the account's Chrome profile unless --no-chrome
#   claude-acct.sh list                   saved accounts, which one is live, refresh-token expiry
#   claude-acct.sh limits                 7-day quota per account, from this machine's latest readings
#   claude-acct.sh record-limits          (from a statusline command) keep this payload's reading
#   claude-acct.sh usage [--days N]       token usage per account, attributed by switch time
#   claude-acct.sh --help
#
# Accounts file (optional; aliases and Chrome profiles): ~/.config/claude-acct/accounts
#   one line per account, tab-separated:  <alias>  <email>  [<chrome profile directory>]
#   The profile directory is the last segment of "Profile Path" on chrome://version
#   ("Default", "Profile 1", ...).
#
# State: ~/.local/state/claude-acct/switches.jsonl — one line per switch, {ts, from, to}. The
# usage report attributes transcript tokens to whichever account was live at each message.
#
# Guards: an email must be a plain address (it becomes part of a keychain service name, and
# `security -i` re-tokenizes quotes); one save/add/use runs at a time (a lock under the state
# dir: a symlink whose target is the owner's pid, so the pid exists the instant the lock does).
#
# Exit codes: 0 ok · 1 usage error · 2 refused (precondition failed, nothing changed — a slot
#             write that fails is put back, and the message says so if even that fails) ·
#             3 switch failed and the original token and identity were restored ·
#             4 restore ALSO failed.

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
kc_read() {   # $1 service → value on stdout for capture; rc 0 found, 1 absent
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
restore_both() {  # $1 the original credential, $2 the original oauthAccount → rc 0 if both are back
  local _ok=0
  printf '%s' "$1" | kc_write "$LIVE_SERVICE" || _ok=1
  # Only rewrite the identity if it moved: a write that never landed needs no undo, and an
  # unconditional rewrite would turn "the write failed" into "the restore failed" (exit 4).
  if [ "$(live_account | jq -cS . 2>/dev/null)" != "$(printf '%s' "$2" | jq -cS .)" ]; then
    ccj_set_account "$2" || _ok=1
  fi
  return "$_ok"
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
  local target="" chrome=1 a
  for a in "$@"; do
    case "$a" in
      --no-chrome) chrome=0 ;;
      -*) die 1 "unknown flag: $a" ;;
      *) [ -z "$target" ] || die 1 "use takes one account"; target="$a" ;;
    esac
  done
  [ -n "$target" ] || die 1 "usage: claude-acct.sh use <alias|email> [--no-chrome]"
  local email; email=$(resolve_email "$target") \
    || die 1 "'$target' is neither a plain email address nor an alias in $CONF"

  take_lock
  local cur; cur=$(live_email)
  [ -n "$cur" ] || die 2 "$(no_account_why) — cannot tell which slot the live token belongs to"
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
    if ! printf '%s' "$_new" | kc_write "$LIVE_SERVICE" \
       || ! ccj_set_account "$_acct" \
       || ! same_email "$(confirmed_email)" "$email"; then
      if restore_both "$_orig" "$_orig_acct"; then
        die 3 "switch to $email failed; the original token and identity are restored ($cur)"
      fi
      die 4 "switch to $email failed AND restoring $cur failed — run: claude auth login --email $cur"
    fi
    record_switch "$cur" "$email"
    printf 'switched %s -> %s\n' "$cur" "$email"
    note "new sessions start on $email; running sessions move at their next request (if one does not: /exit, then claude --continue)"
    [ -e "$CCD/.credentials.json" ] \
      && note "$CCD/.credentials.json exists — running sessions read it instead of the keychain; move it aside"
  fi

  if [ "$chrome" -eq 1 ]; then
    local prof
    if prof=$(chrome_profile_of "$email"); then
      open -na "Google Chrome" --args --profile-directory="$prof" \
        || note "could not open Chrome profile '$prof'"
    else
      note "no Chrome profile set for $email in $CONF (third column) — skipped"
    fi
  fi
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
  local cur; cur=$(live_email)
  if [ -z "$cur" ]; then
    local _st; _st=$(live_state)
    [ "$_st" = out ] || note "$(no_account_why "$_st") — no account is marked live below"
  fi
  local e
  local now; now=$(date +%s)
  known_emails "$cur" | while IFS= read -r e; do
    local mark=" " saved="no saved token" raw="" bad="" exp="" days="" expiry=""
    [ "$e" = "$cur" ] && mark="*"
    if raw=$(kc_read "$SLOT_PREFIX$e"); then
      saved="saved"
      bad=$(slot_problem "$raw" "$e")
      [ -z "$bad" ] || saved="saved, $bad — re-run: claude-acct.sh add $e"
      # refreshTokenExpiresAt is epoch milliseconds; past it, the slot cannot sign in at all.
      exp=$(printf '%s' "$raw" | jq -r '.claudeAiOauth.refreshTokenExpiresAt // empty | numbers | . / 1000 | floor' 2>/dev/null)
      if [ -n "$exp" ]; then
        days=$(( (exp - now) / 86400 ))
        expiry="; refresh token until $(date -r "$exp" +%Y-%m-%d)"
        if [ "$exp" -le "$now" ]; then expiry="$expiry — EXPIRED, re-run: claude-acct.sh add $e"
        elif [ "$days" -le 7 ]; then expiry="$expiry — EXPIRES IN ${days}d, re-run: claude-acct.sh add $e"
        fi
      else
        expiry="; refresh-token expiry unknown"
      fi
    fi
    printf '%s %-40s %s%s\n' "$mark" "$e" "$saved" "$expiry"
  done
}

# 7-day quota per known account, from the newest reading `record-limits` kept for it:
# ~/.cache/claude-limits/latest/<email>.json. No network and no secret: an account no session on
# this machine has used since recording began has no reading, and says so rather than printing 0%.
cmd_limits() {
  [ $# -eq 0 ] || die 1 "limits takes no arguments"
  local dir="${CLAUDE_ACCT_LIMITS_DIR:-$HOME/.cache/claude-limits}/latest" cur
  cur=$(live_email)
  known_emails "$cur" | python3 -I -c '
import datetime as dt, json, os, sys, time
d, cur = sys.argv[1], sys.argv[2]
now = time.time()
def when(t):
    return dt.datetime.fromtimestamp(t).astimezone().strftime("%a %b %-d %-I:%M %p %Z")
def age(s):
    s = max(0, int(s))
    if s < 90: return f"{s}s"
    if s < 5400: return f"{s // 60}m"
    if s < 172800: return f"{s // 3600}h"
    return f"{s // 86400}d"
def stamp(iso):
    return dt.datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()
since = None
try:
    since = open(os.path.join(d, ".since")).read().strip()
except OSError:
    pass
emails = [l.strip() for l in sys.stdin if l.strip()]
if not emails:
    print("no accounts known yet (none in the accounts file, the switch log, or live)")
for e in emails:
    mark = "*" if e == cur else " "
    try:
        r = json.load(open(os.path.join(d, e + ".json")))
    except (OSError, ValueError):
        r = None
    if not r or r.get("seven_day_pct") is None:
        if since:
            line = "no reading since " + when(stamp(since))
        else:
            line = "no readings recorded yet"
    else:
        pct, reset = r["seven_day_pct"], r.get("seven_day_resets_at")
        try:
            got = age(now - stamp(r["captured_at"]))
        except (KeyError, ValueError):
            got = "?"
        if reset and reset > now:
            line = f"{pct:g}% of 7-day used, resets {when(reset)}"
        elif reset:
            line = f"7-day window reset {when(reset)}; {pct:g}% before it, nothing read since"
        else:
            line = f"{pct:g}% of 7-day used, reset time unknown"
        fh, fr = r.get("five_hour_pct"), r.get("five_hour_resets_at")
        if fh is not None and fr and fr > now:
            line += f"; 5-hour {fh:g}%"
        line += f" (reading {got} old)"
    print(f"{mark} {e:40} {line}")
print("Readings come from this machine'"'"'s Claude Code sessions" + (f", kept since {when(stamp(since))}." if since else "; none kept yet."))
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
# A reading with no 5-hour figure (Ultra plans dropped that window) is kept as is; `limits` shows
# only the windows a reading has. A reading with no 7-day figure is not kept.
cmd_record_limits() {
  local base="${CLAUDE_ACCT_LIMITS_DIR:-$HOME/.cache/claude-limits}" input line email reset idc
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
  case "$reset" in
    ''|*[!0-9]*) : ;;
    *)
      if [ "$(jq -r '.seven_day_resets_at // empty' "$base/latest/$email.json" 2>/dev/null)" != "$reset" ]; then
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
  ( umask 077
    [ -e "$base/latest/.since" ] || date -u +%Y-%m-%dT%H:%M:%SZ > "$base/latest/.since"
    printf '%s\n' "$line" > "$base/latest/.$email.$$" \
      && mv -f "$base/latest/.$email.$$" "$base/latest/$email.json" \
      || rm -f "$base/latest/.$email.$$" ) 2>/dev/null
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
  list)   cmd_list ;;
  limits) cmd_limits "$@" ;;
  record-limits) cmd_record_limits; exit 0 ;;
  usage)  cmd_usage "$@" ;;
  *) die 1 "unknown subcommand: $sub (try --help)" ;;
esac
