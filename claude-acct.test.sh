#!/bin/bash
# Hermetic tests for claude-acct.sh. Never touches the real keychain:
# `security`, `claude`, and `open` are stubs on PATH, the keychain is a JSON file, and HOME and
# CLAUDE_CONFIG_DIR are temp dirs.
#
# The `security` stub reproduces the two transport facts the script depends on, both measured on
# this machine: `security -i` truncates a line past 4032 chars and exits 1, and argv `-X <hex>`
# carries any size. So a script that sent a large item through -i fails here, as it would live.
#
# The `claude` stub keeps identity where the real CLI does: `auth status` reads the
# email from `.claude.json` `oauthAccount`, never from the token, which carries none. So a
# script that moved only the token reports the OLD account here, exactly as it did live.

set -u
SCRIPT="$(cd "$(dirname "$0")" && pwd)/claude-acct.sh"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s\n       %s\n' "$1" "${2:-}"; }

new_env() {
  T=$(mktemp -d)
  export HOME="$T/home" CLAUDE_CONFIG_DIR="$T/cfg" USER=tester
  mkdir -p "$HOME" "$CLAUDE_CONFIG_DIR/projects" "$T/bin"
  export STUB_KC="$T/keychain.json" STUB_OPEN_LOG="$T/open.log" STUB_ARGV_LOG="$T/argv.log"
  STUB_LIVE="Claude Code-credentials-$(printf '%s' "$CLAUDE_CONFIG_DIR" | shasum -a 256 | cut -c1-8)"
  export STUB_LIVE CCJ="$CLAUDE_CONFIG_DIR/.claude.json"
  unset STUB_FAIL_WRITE STUB_CORRUPT_WRITE STUB_LOGIN_AS STUB_STATUS_EMAIL STUB_STATUS_SCRIPT STUB_STATUS_MODE \
        STUB_CCJ_TOUCH CLAUDE_ACCT_CCJ_LOCK_WAIT BROWSER CLAUDE_SECURESTORAGE_CONFIG_DIR
  export CLAUDE_ACCT_RETRY_SLEEP=0
  echo '{}' > "$STUB_KC"
  cat > "$T/bin/security" <<'PY'
#!/usr/bin/env python3
import json, os, shlex, sys
db = os.environ["STUB_KC"]
def load(): return json.load(open(db))
def save(d): json.dump(d, open(db, "w"))
def opts(a):
    o, i = {}, 0
    while i < len(a):
        if a[i] in ("-s", "-a", "-X", "-w") and i + 1 < len(a): o[a[i]] = a[i+1]; i += 2
        else: o[a[i]] = True; i += 1
    return o
def run(a):
    cmd, o = a[0], opts(a[1:])
    key = f'{o.get("-s")}|{o.get("-a")}'
    d = load()
    if cmd == "find-generic-password":
        if key not in d: return 44
        if "-w" in o: print(d[key])
        return 0
    if cmd == "add-generic-password":
        if key in d and "-U" not in o: return 45
        val = bytes.fromhex(o["-X"]).decode() if "-X" in o else o.get("-w", "")
        if os.environ.get("STUB_FAIL_WRITE") == o.get("-s"): return 0   # silent non-persist
        if os.environ.get("STUB_CORRUPT_WRITE") == o.get("-s"): val = val[:-1]  # lands damaged
        d[key] = val; save(d)
        # A running session writing .claude.json between the token write and the identity write.
        if os.environ.get("STUB_CCJ_TOUCH") and o.get("-s") == os.environ["STUB_LIVE"]:
            p = os.environ["CCJ"]; c = json.load(open(p)); c["concurrent"] = True
            json.dump(c, open(p, "w"))
        return 0
    if cmd == "delete-generic-password":
        d.pop(key, None); save(d); return 0
    return 2
a = sys.argv[1:]
with open(os.environ["STUB_ARGV_LOG"], "a") as f: f.write(json.dumps(a) + "\n")
if a[:1] == ["-i"]:
    rc = 0
    for line in sys.stdin:
        if len(line.rstrip("\n")) > 4032:
            rc = 1; continue                      # measured: truncation, exit 1
        rc = run(shlex.split(line)) or rc
    sys.exit(rc)
sys.exit(run(a))
PY
  cat > "$T/bin/claude" <<'PY'
#!/usr/bin/env python3
import hashlib, json, os, subprocess, sys
# Resolve the keychain item and identity file the way the real CLI does (read from the 2.1.314
# binary, re-measured 2026-11-01 under `env -i`): the service is `Claude Code-credentials`, plus
# `-<sha256(dir)[0:8]>` only when CLAUDE_SECURESTORAGE_CONFIG_DIR (an empty value drops the suffix)
# or CLAUDE_CONFIG_DIR is set; the identity is $CLAUDE_CONFIG_DIR/.claude.json, else ~/.claude.json;
# the item's account is $USER, and with USER unset the CLI finds no claude.ai item and reports no
# email. So a script that does not hand its own resolution to `claude` reads the wrong record here.
h8 = lambda v: "-" + hashlib.sha256(v.encode()).hexdigest()[:8]
env = os.environ
if "CLAUDE_SECURESTORAGE_CONFIG_DIR" in env:
    sfx = h8(env["CLAUDE_SECURESTORAGE_CONFIG_DIR"]) if env["CLAUDE_SECURESTORAGE_CONFIG_DIR"] else ""
elif env.get("CLAUDE_CONFIG_DIR"):
    sfx = h8(env["CLAUDE_CONFIG_DIR"])
else:
    sfx = ""
db = env["STUB_KC"]
live = "Claude Code-credentials" + sfx + "|" + env.get("USER", "")
ccj = os.path.join(env["CLAUDE_CONFIG_DIR"], ".claude.json") if env.get("CLAUDE_CONFIG_DIR") \
      else os.path.join(env["HOME"], ".claude.json")
a = sys.argv[1:]
d = json.load(open(db))
def ccj_load():
    try: return json.load(open(ccj))
    except Exception: return None
if a[:2] == ["auth", "status"]:
    try: tok = json.loads(d[live])["claudeAiOauth"]
    except Exception: tok = None
    c = ccj_load()
    try: email = c["oauthAccount"]["emailAddress"] if tok else None
    except Exception: email = None
    email = os.environ.get("STUB_STATUS_EMAIL", email)
    script = os.environ.get("STUB_STATUS_SCRIPT")        # e.g. "ok fail": one outcome per call
    if script and os.path.exists(script):
        steps = open(script).read().split()
        if steps:
            open(script, "w").write(" ".join(steps[1:]))
            if steps[0] == "fail": email = None
            elif steps[0].startswith("as:"): email = steps[0][3:]   # the account changed underneath
    mode = os.environ.get("STUB_STATUS_MODE")
    if mode == "noemail":   # measured under launchd: logged in, the CLI names no account
        print(json.dumps({"loggedIn": True, "email": None, "authMethod": "oauth_token"})); sys.exit(0)
    if mode == "raw":       # the CLI failed and printed no JSON
        print("Error: auth status failed"); sys.exit(1)
    if mode == "object":    # an object with no loggedIn: not a logged-out reply
        print(json.dumps({"error": "auth status failed"})); sys.exit(0)
    if mode == "bare-token" and not email:   # measured: no account signed in under this config
        print(json.dumps({"loggedIn": True, "authMethod": "oauth_token"})); sys.exit(0)   # dir, yet loggedIn
    print(json.dumps({"loggedIn": bool(email), "email": email})); sys.exit(0)
if a[:2] == ["auth", "login"]:
    if os.environ.get("BROWSER"):
        subprocess.run([os.environ["BROWSER"], "https://claude.ai/oauth/authorize?x=1"])
    who = os.environ.get("STUB_LOGIN_AS") or a[a.index("--email") + 1]
    cur = json.loads(d.get(live, "{}"))
    cur["claudeAiOauth"] = {"accessToken": "TOK-" + who + "-fresh", "refreshTokenExpiresAt": 4102444800000}
    d[live] = json.dumps(cur); json.dump(d, open(db, "w"))
    c = ccj_load() or {}
    c["oauthAccount"] = {"emailAddress": who, "accountUuid": "uuid-" + who}
    json.dump(c, open(ccj, "w")); sys.exit(0)
sys.exit(2)
PY
  # One argv element per line, so a lost quote (Google / Chrome as two tokens) is visible.
  printf '#!/bin/bash\nprintf "%%s\\n" "$@" >> "$STUB_OPEN_LOG"\n' > "$T/bin/open"
  chmod +x "$T/bin/"*
  export PATH="$T/bin:/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"
  mkdir -p "$HOME/.config/claude-acct"
  printf 'home\thome@example.com\tDefault\nwork\twork@example.com\tProfile 1\n' \
    > "$HOME/.config/claude-acct/accounts"
}
# seed the live records: a token + per-machine keys that must never move, and the identity in
# .claude.json next to an unrelated key that must survive every write
seed_live() {  # $1 email  $2 pad-bytes (to force the argv branch)
  python3 - "$1" "${2:-0}" <<'PY'
import json, os, sys
d = json.load(open(os.environ["STUB_KC"]))
d[os.environ["STUB_LIVE"] + "|" + os.environ["USER"]] = json.dumps({
  "claudeAiOauth": {"accessToken": "TOK-" + sys.argv[1], "refreshTokenExpiresAt": 4102444800000},
  "mcpOAuth": {"linear": {"accessToken": "MCP-LINEAR-SECRET"}, "pad": "p" * int(sys.argv[2])},
  "coworkRemoteDevice": {"d1": {"privateKeyPkcs8B64": "DEVKEY-SECRET"}}})
json.dump(d, open(os.environ["STUB_KC"], "w"))
json.dump({"oauthAccount": {"emailAddress": sys.argv[1], "accountUuid": "uuid-" + sys.argv[1]},
           "projects": {"/x": {"k": 1}}}, open(os.environ["CCJ"], "w"))
PY
  chmod 600 "$CCJ"
}
seed_slot() {  # $1 email  [$2 "noacct" = the pre-identity shape | "acct:<email>"]  [$3 days to refresh expiry]
  python3 - "$1" "${2:-}" "${3:-400}" <<'PY'
import json, os, sys, time
email, mode, days = sys.argv[1], sys.argv[2], float(sys.argv[3])
slot = {"claudeAiOauth": {"accessToken": "TOK-" + email + "-slot",
                          "refreshTokenExpiresAt": int((time.time() + days * 86400) * 1000)}}
if mode != "noacct":
    who = mode[5:] if mode.startswith("acct:") else email
    slot["oauthAccount"] = {"emailAddress": who, "accountUuid": "uuid-" + who}
d = json.load(open(os.environ["STUB_KC"]))
d["claude-acct/" + email + "|" + os.environ["USER"]] = json.dumps(slot)
json.dump(d, open(os.environ["STUB_KC"], "w"))
PY
}
kc_get() {  # $1 service  $2 jq path
  jq -r --arg k "$1|$USER" '.[$k] // empty' "$STUB_KC" | { [ -n "${2:-}" ] && jq -r "$2" || cat; }
}
live_hash_of_machine_keys() { kc_get "$STUB_LIVE" | jq -cS '{mcpOAuth, coworkRemoteDevice}' | shasum | cut -c1-12; }
ccj_email() { jq -r '.oauthAccount.emailAddress // empty' "$CCJ" 2>/dev/null; }
snapshot() { cat "$STUB_KC"; printf '\n--ccj--\n'; cat "$CCJ" 2>/dev/null || printf 'ABSENT'; }

printf 'claude-acct.sh\n'

# 1 — the switch moves the token AND the identity; MCP logins, device keys, and other
#     .claude.json keys stay byte-identical
new_env; seed_live home@example.com; seed_slot work@example.com
before=$(live_hash_of_machine_keys); projects_before=$(jq -cS .projects "$CCJ")
out=$(bash "$SCRIPT" use work 2>&1); rc=$?
[ $rc -eq 0 ] && [ "$(kc_get "$STUB_LIVE" .claudeAiOauth.accessToken)" = "TOK-work@example.com-slot" ] \
  && ok "use work: the live token is the work slot's" || bad "use work did not switch the token" "rc=$rc $out"
[ "$(ccj_email)" = "work@example.com" ] \
  && [ "$(claude auth status --json | jq -r .email)" = "work@example.com" ] \
  && ok "use work: .claude.json and claude auth status name the target" \
  || bad "the identity did not move with the token" "ccj=$(ccj_email)"
[ "$(jq -cS .projects "$CCJ")" = "$projects_before" ] \
  && ok "every other .claude.json key is untouched" || bad "a .claude.json key changed"
[ "$(stat -f %Lp "$CCJ")" = "600" ] && ok ".claude.json keeps its 0600 mode" || bad ".claude.json mode" "$(stat -f %Lp "$CCJ")"
[ ! -e "$CCJ.lock" ] && ok "the config lock is released" || bad "the config lock was left behind"
[ "$(live_hash_of_machine_keys)" = "$before" ] \
  && ok "MCP logins and device keys are untouched by the switch" \
  || bad "a switch changed per-machine keys" "MCP/device keys must never move with the account"
[ "$(kc_get "claude-acct/home@example.com" .claudeAiOauth.accessToken)" = "TOK-home@example.com" ] \
  && ok "the outgoing account's CURRENT token was parked in its slot" \
  || bad "outgoing token not saved" "a refreshed token would be lost on switch-back"
[ "$(kc_get "claude-acct/home@example.com" 'keys|join(",")')" = "claudeAiOauth,oauthAccount" ] \
  && [ "$(kc_get "claude-acct/home@example.com" .oauthAccount.emailAddress)" = "home@example.com" ] \
  && ok "a slot holds the token and its identity, never MCP logins" || bad "slot shape wrong" "$(kc_get "claude-acct/home@example.com" 'keys|join(",")')"
[ "$(tr '\n' '|' < "$STUB_OPEN_LOG" 2>/dev/null)" = "-na|Google Chrome|--args|--profile-directory=Profile 1|" ] \
  && ok "opens the target's Chrome profile" || bad "Chrome profile not opened" "$(cat "$STUB_OPEN_LOG" 2>/dev/null)"
[ "$(jq -r '"\(.from)>\(.to)"' "$HOME/.local/state/claude-acct/switches.jsonl" 2>/dev/null)" = "home@example.com>work@example.com" ] \
  && ok "the switch is recorded for usage attribution" || bad "switch not recorded"
case "$out" in *TOK-*|*MCP-LINEAR-SECRET*|*DEVKEY-SECRET*) bad "use printed a credential" "$out" ;;
  *) ok "use prints no credential" ;; esac
case "$out" in *"running sessions move at their next request"*) ok "use says when a running session moves" ;;
  *) bad "use does not say running sessions follow at their next request" "$out" ;; esac
rm -rf "$T"

# 2 — switch back restores the first account's token AND identity from its slot
new_env; seed_live home@example.com; seed_slot work@example.com
bash "$SCRIPT" use work --no-chrome >/dev/null 2>&1; bash "$SCRIPT" use home --no-chrome >/dev/null 2>&1; rc=$?
[ $rc -eq 0 ] && [ "$(kc_get "$STUB_LIVE" .claudeAiOauth.accessToken)" = "TOK-home@example.com" ] \
  && [ "$(ccj_email)" = "home@example.com" ] \
  && ok "round trip home -> work -> home restores the original token and identity" || bad "round trip lost a record" "rc=$rc"
[ ! -s "$STUB_OPEN_LOG" ] && ok "--no-chrome opens nothing" || bad "--no-chrome still opened Chrome"
rm -rf "$T"

# 3 — no saved token for the target: refuse, change nothing
new_env; seed_live home@example.com
snap=$(snapshot)
bash "$SCRIPT" use work --no-chrome >/dev/null 2>&1; rc=$?
[ $rc -eq 2 ] && [ "$(snapshot)" = "$snap" ] \
  && ok "missing slot: exit 2 and nothing changed" || bad "missing slot not refused cleanly" "rc=$rc"
rm -rf "$T"

# 3b — a pre-identity slot (token, no identity) is refused, never switched to with a guessed identity
new_env; seed_live home@example.com; seed_slot work@example.com noacct
snap=$(snapshot)
out=$(bash "$SCRIPT" use work --no-chrome 2>&1); rc=$?
[ $rc -eq 2 ] && [ "$(snapshot)" = "$snap" ] \
  && case "$out" in *"re-run: claude-acct.sh add work@example.com"*) true ;; *) false ;; esac \
  && ok "a slot with no identity is refused with the add command, nothing changed" \
  || bad "an identity-less slot was not refused" "rc=$rc $out"
rm -rf "$T"

# 3c — a slot whose identity names another account is refused
new_env; seed_live home@example.com; seed_slot work@example.com acct:someone@else.com
snap=$(snapshot)
bash "$SCRIPT" use work --no-chrome >/dev/null 2>&1; rc=$?
[ $rc -eq 2 ] && [ "$(snapshot)" = "$snap" ] \
  && ok "a slot whose identity names another account is refused" || bad "a mismatched slot was used" "rc=$rc"
rm -rf "$T"

# 3d — the live identity disagrees with what claude reports: refuse before parking anything
new_env; seed_live home@example.com; seed_slot work@example.com
jq '.oauthAccount.emailAddress = "stale@example.com"' "$CCJ" > "$CCJ.x" && mv "$CCJ.x" "$CCJ"
export STUB_STATUS_EMAIL=home@example.com
snap=$(snapshot)
bash "$SCRIPT" use work --no-chrome >/dev/null 2>&1; rc=$?
unset STUB_STATUS_EMAIL
[ $rc -eq 2 ] && [ "$(snapshot)" = "$snap" ] \
  && ok "live identity disagreeing with auth status is refused" || bad "a disagreeing identity was parked" "rc=$rc"
rm -rf "$T"

# 3e — a missing or corrupt .claude.json is refused and never created or truncated
new_env; seed_live home@example.com; seed_slot work@example.com
rm -f "$CCJ"; export STUB_STATUS_EMAIL=home@example.com
bash "$SCRIPT" use work --no-chrome >/dev/null 2>&1; rc=$?
[ $rc -eq 2 ] && [ ! -e "$CCJ" ] && ok "a missing .claude.json is refused, never created" || bad "missing .claude.json" "rc=$rc"
printf '{"oauthAccount": {' > "$CCJ"; snap=$(snapshot)
bash "$SCRIPT" use work --no-chrome >/dev/null 2>&1; rc=$?
unset STUB_STATUS_EMAIL
[ $rc -eq 2 ] && [ "$(snapshot)" = "$snap" ] && ok "a corrupt .claude.json is refused, left as it was" || bad "corrupt .claude.json" "rc=$rc"
rm -rf "$T"

# 4 — the live write silently does not persist: restore attempted, exit 3 names it
new_env; seed_live home@example.com; seed_slot work@example.com
export STUB_FAIL_WRITE="$STUB_LIVE"
bash "$SCRIPT" use work --no-chrome >/dev/null 2>&1; rc=$?
unset STUB_FAIL_WRITE
[ "$(kc_get "$STUB_LIVE" .claudeAiOauth.accessToken)" = "TOK-home@example.com" ] && [ "$(ccj_email)" = "home@example.com" ] \
  && ok "a write that did not land leaves the original account live" || bad "failed write corrupted the live records"
[ $rc -eq 3 ] && ok "and exits 3: the item never changed, so the restore reads back intact" \
  || bad "a failed live write must not report success" "rc=$rc"
rm -rf "$T"

# 4b — every live write lands CORRUPTED: the switch and the restore both fail read-back, exit 4
new_env; seed_live home@example.com; seed_slot work@example.com
export STUB_CORRUPT_WRITE="$STUB_LIVE"
out=$(bash "$SCRIPT" use work --no-chrome 2>&1); rc=$?
unset STUB_CORRUPT_WRITE
[ $rc -eq 4 ] && case "$out" in *"claude auth login --email home@example.com"*) true ;; *) false ;; esac \
  && ok "restore failure exits 4 and names the recovery command" \
  || bad "an unrecoverable switch was not reported as exit 4" "rc=$rc $out"
rm -rf "$T"

# 4c — the token lands and the config lock is taken, but the rename fails: restore BOTH, exit 3,
#      and neither the lock nor the temp file is left behind
new_env; seed_live home@example.com; seed_slot work@example.com
printf '#!/bin/bash\n[ -n "${STUB_MV_FAIL:-}" ] && exit 1\nexec /bin/mv "$@"\n' > "$T/bin/mv"; chmod +x "$T/bin/mv"
export STUB_MV_FAIL=1
out=$(bash "$SCRIPT" use work --no-chrome 2>&1); rc=$?
unset STUB_MV_FAIL
set -- "$CLAUDE_CONFIG_DIR"/.claude.json.claude-acct.*.tmp
[ $rc -eq 3 ] && [ "$(kc_get "$STUB_LIVE" .claudeAiOauth.accessToken)" = "TOK-home@example.com" ] \
  && [ "$(ccj_email)" = "home@example.com" ] && [ ! -e "$CCJ.lock" ] && [ ! -e "$1" ] \
  && case "$out" in *"could not rewrite"*) true ;; *) false ;; esac \
  && ok "identity write failure after the lock restores BOTH, exit 3, leaves no lock or temp file" \
  || bad "a failed identity write left a mixed account or debris" "rc=$rc $out"
rm -rf "$T"
# 4c2 — the config lock wait times out: the cause is named, not just "switch failed"
new_env; seed_live home@example.com; seed_slot work@example.com
mkdir "$CCJ.lock"; export CLAUDE_ACCT_CCJ_LOCK_WAIT=0
out=$(bash "$SCRIPT" use work --no-chrome 2>&1); rc=$?
unset CLAUDE_ACCT_CCJ_LOCK_WAIT
[ $rc -eq 3 ] && case "$out" in *"config lock"*"still held"*) true ;; *) false ;; esac \
  && ok "a config-lock timeout says so" || bad "config-lock timeout not named" "rc=$rc $out"
rm -rf "$T"
# 4c3 — a leading-zero wait ("08", invalid octal to $(( ))) falls back to a working wait: the
#       lock is released after ~1s and the switch completes instead of dying on arithmetic
new_env; seed_live home@example.com; seed_slot work@example.com
mkdir "$CCJ.lock"; export CLAUDE_ACCT_CCJ_LOCK_WAIT=08
( sleep 1; rmdir "$CCJ.lock" ) &
bash "$SCRIPT" use work --no-chrome >/dev/null 2>&1; rc=$?
wait; unset CLAUDE_ACCT_CCJ_LOCK_WAIT
[ $rc -eq 0 ] && [ "$(ccj_email)" = "work@example.com" ] \
  && ok "a leading-zero lock wait falls back to a working wait" || bad "leading-zero lock wait broke the switch" "rc=$rc"
rm -rf "$T"

# 4d — Claude Code's config lock is held throughout: wait, give up, restore, exit 3
new_env; seed_live home@example.com; seed_slot work@example.com
mkdir "$CCJ.lock"; export CLAUDE_ACCT_CCJ_LOCK_WAIT=1
bash "$SCRIPT" use work --no-chrome >/dev/null 2>&1; rc=$?
unset CLAUDE_ACCT_CCJ_LOCK_WAIT
[ $rc -eq 3 ] && [ "$(kc_get "$STUB_LIVE" .claudeAiOauth.accessToken)" = "TOK-home@example.com" ] \
  && [ "$(ccj_email)" = "home@example.com" ] && [ -d "$CCJ.lock" ] \
  && ok "a held config lock is waited for, then given up on with a restore (and never stolen)" \
  || bad "the config lock was not honored" "rc=$rc"
rm -rf "$T"

# 4e — a running session writes .claude.json after the token write: its key survives the swap
new_env; seed_live home@example.com; seed_slot work@example.com
export STUB_CCJ_TOUCH=1
bash "$SCRIPT" use work --no-chrome >/dev/null 2>&1; rc=$?
unset STUB_CCJ_TOUCH
[ $rc -eq 0 ] && [ "$(jq -r .concurrent "$CCJ")" = "true" ] && [ "$(ccj_email)" = "work@example.com" ] \
  && ok "a concurrent key written before the swap survives it (re-read under the lock)" \
  || bad "the identity write clobbered a concurrent write" "rc=$rc"
rm -rf "$T"

# 5 — both writes land but claude reports another account: roll back both, exit 3
# Calls 1-2 are the pre-switch reads; 3-5 are the three post-write confirmation tries.
new_env; seed_live home@example.com; seed_slot work@example.com
export STUB_STATUS_SCRIPT="$T/status-script"
printf 'ok ok as:someone@else.com as:someone@else.com as:someone@else.com' > "$STUB_STATUS_SCRIPT"
bash "$SCRIPT" use work --no-chrome >/dev/null 2>&1; rc=$?
unset STUB_STATUS_SCRIPT
[ $rc -eq 3 ] && [ "$(kc_get "$STUB_LIVE" .claudeAiOauth.accessToken)" = "TOK-home@example.com" ] \
  && [ "$(ccj_email)" = "home@example.com" ] \
  && ok "a switch claude does not confirm is rolled back, both records, exit 3" \
  || bad "an unconfirmed switch was left in place" "rc=$rc"
rm -rf "$T"

# 6 — transport: a large item goes via argv -X, a small one via -i (the measured 4032 limit)
new_env; seed_live home@example.com 6000; seed_slot work@example.com
bash "$SCRIPT" use work --no-chrome >/dev/null 2>&1; rc=$?
[ $rc -eq 0 ] && [ "$(kc_get "$STUB_LIVE" .mcpOAuth.pad | wc -c | tr -d ' ')" = "6001" ] \
  && ok "a ~6 KB live item switches intact (argv branch)" || bad "large item failed or truncated" "rc=$rc"
grep -q '"add-generic-password", "-U", "-a", "tester", "-s", "Claude Code-credentials-' "$STUB_ARGV_LOG" \
  && ok "the large live write used argv, like Claude Code does" || bad "large write did not take the argv branch"
grep -q '"add-generic-password", "-U", "-a", "tester", "-s", "claude-acct/' "$STUB_ARGV_LOG" \
  && bad "a small slot write went through argv" "slots fit -i and should never touch argv" \
  || ok "small slot writes stay on stdin (-i)"
rm -rf "$T"

# 7 — add: parks the current account, logs in, saves the new one with its identity
new_env; seed_live home@example.com
out=$(bash "$SCRIPT" add work@example.com 2>&1); rc=$?
[ $rc -eq 0 ] && [ "$(kc_get "claude-acct/work@example.com" .claudeAiOauth.accessToken)" = "TOK-work@example.com-fresh" ] \
  && [ "$(kc_get "claude-acct/work@example.com" .oauthAccount.emailAddress)" = "work@example.com" ] \
  && [ "$(kc_get "claude-acct/home@example.com" .oauthAccount.emailAddress)" = "home@example.com" ] \
  && ok "add saves both the previous and the new account, each with its identity" || bad "add did not save both" "rc=$rc $out"
# 7a — the sign-in page opens in the account's own Chrome profile, through $BROWSER
[ "$(tr '\n' '|' < "$STUB_OPEN_LOG" 2>/dev/null)" = "-na|Google Chrome|--args|--profile-directory=Profile 1|https://claude.ai/oauth/authorize?x=1|" ] \
  && ok "add opens the sign-in URL in the account's Chrome profile" || bad "sign-in not routed to the profile" "$(cat "$STUB_OPEN_LOG" 2>/dev/null)"
case "$out" in *'Chrome profile "Profile 1"'*) ok "add names the profile to sign in with" ;;
  *) bad "add did not name the profile" "$out" ;; esac
set -- "$HOME"/.local/state/claude-acct/browser.*
[ -e "$1" ] && bad "the browser shim was left behind" "$1" || ok "the browser shim is removed on exit"
rm -rf "$T"
new_env; seed_live home@example.com
out=$(bash "$SCRIPT" add other@example.com 2>&1); rc=$?
[ $rc -eq 0 ] && [ ! -s "$STUB_OPEN_LOG" ] && case "$out" in *"no Chrome profile set for other@example.com"*) true ;; *) false ;; esac \
  && ok "add with no profile set still signs in, and says the page opens in the frontmost window" \
  || bad "add without a profile" "rc=$rc $out"
rm -rf "$T"

# 7b — re-adding the account that is already live refreshes its slot and is not a switch
new_env; seed_live home@example.com
out=$(bash "$SCRIPT" add home@example.com 2>&1); rc=$?
[ $rc -eq 0 ] && [ "$(kc_get "claude-acct/home@example.com" .oauthAccount.emailAddress)" = "home@example.com" ] \
  && [ ! -e "$HOME/.local/state/claude-acct/switches.jsonl" ] \
  && case "$out" in *"switch back"*) false ;; *"already live"*) true ;; *) false ;; esac \
  && ok "re-adding the live account refreshes its slot, records no switch, offers no switch-back" \
  || bad "re-add of the live account treated as a switch" "rc=$rc $out"
rm -rf "$T"

new_env; seed_live home@example.com; export STUB_LOGIN_AS=home@example.com
bash "$SCRIPT" add work@example.com >/dev/null 2>&1; rc=$?
unset STUB_LOGIN_AS
[ $rc -eq 2 ] && [ -z "$(kc_get "claude-acct/work@example.com")" ] \
  && ok "add refuses when the login landed on a different account" \
  || bad "add saved a slot under the wrong email" "rc=$rc"
rm -rf "$T"

# 8 — aliases and argument errors
new_env; seed_live home@example.com
bash "$SCRIPT" use nosuch --no-chrome >/dev/null 2>&1; [ $? -eq 1 ] && ok "unknown alias: exit 1" || bad "unknown alias not rejected"
bash "$SCRIPT" use home --no-chrome >/dev/null 2>&1; rc=$?
[ $rc -eq 0 ] && [ ! -e "$HOME/.local/state/claude-acct/switches.jsonl" ] \
  && ok "switching to the live account writes nothing and records no switch" || bad "no-op switch was not a no-op" "rc=$rc"
bash "$SCRIPT" add notanemail >/dev/null 2>&1; [ $? -eq 1 ] && ok "add rejects a non-email" || bad "add accepted a non-email"
rm -rf "$T"

# 9 — list shows each account, marks the live one, shows refresh-token expiry, prints no credential
new_env; seed_live home@example.com; seed_slot work@example.com "" 30
printf 'soon\tsoon@example.com\nold\told@example.com\nmix\tmix@example.com\n' >> "$HOME/.config/claude-acct/accounts"
seed_slot soon@example.com "" 3.5; seed_slot old@example.com noacct 30; seed_slot mix@example.com acct:other@example.com 30
out=$(bash "$SCRIPT" list 2>&1)
d30=$(date -r $(( $(date +%s) + 30 * 86400 )) +%Y-%m-%d)
printf '%s\n' "$out" | grep -qE '^\* home@example.com +no saved token' \
  && printf '%s\n' "$out" | grep -qE "^  work@example.com +saved; refresh token until $d30\$" \
  && ok "list marks the live account and shows a slot's refresh-token date" || bad "list output wrong" "$out"
printf '%s\n' "$out" | grep -qE '^  soon@example.com +saved; refresh token until [0-9-]+ — EXPIRES IN 3d, re-run: claude-acct.sh add soon@example.com$' \
  && ok "list flags a refresh token within 7 days" || bad "near expiry not flagged" "$out"
printf '%s\n' "$out" | grep -qE '^  old@example.com +saved, no identity — re-run: claude-acct.sh add old@example.com' \
  && ok "list flags a slot with no identity" || bad "identity-less slot not flagged" "$out"
printf '%s\n' "$out" | grep -qE "^  mix@example.com +saved, identity of 'other@example.com' — re-run: claude-acct.sh add mix@example.com" \
  && ok "list flags a slot use would refuse for a mismatched identity" || bad "mismatched slot shown as usable" "$out"
case "$out" in *TOK-*) bad "list printed a token" ;; *) ok "list prints no credential" ;; esac
rm -rf "$T"

# 10 — usage: tokens attributed by switch time, duplicate message records counted once
new_env; seed_live work@example.com
mkdir -p "$CLAUDE_CONFIG_DIR/projects/p"
now=$(date -u +%s)
iso() { date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ; }
mkdir -p "$HOME/.local/state/claude-acct"
jq -cn --arg ts "$(iso $((now-3600)))" '{ts:$ts,from:"home@example.com",to:"work@example.com"}' \
  > "$HOME/.local/state/claude-acct/switches.jsonl"
{
  for spec in "m1 $((now-5400)) 100" "m1 $((now-5390)) 100" "m2 $((now-1800)) 7"; do
    set -- $spec
    jq -cn --arg id "$1" --arg ts "$(iso "$2")" --argjson o "$3" \
      '{type:"assistant",timestamp:$ts,message:{id:$id,usage:{input_tokens:1,output_tokens:$o}}}'
  done
} > "$CLAUDE_CONFIG_DIR/projects/p/s.jsonl"
# a subagent transcript, one level deeper, as the CLI lays them out
mkdir -p "$CLAUDE_CONFIG_DIR/projects/p/sess/subagents"
jq -cn --arg ts "$(iso $((now-1700)))" \
  '{type:"assistant",timestamp:$ts,message:{id:"m3",usage:{input_tokens:1,output_tokens:5}}}' \
  > "$CLAUDE_CONFIG_DIR/projects/p/sess/subagents/agent-x.jsonl"
out=$(bash "$SCRIPT" usage --days 1 2>&1)
printf '%s\n' "$out" | grep -qE '^home@example.com +1 +1 +100 ' \
  && ok "usage before the switch goes to the FROM account, counted once despite a duplicate record" \
  || bad "pre-switch attribution or dedup wrong" "$out"
printf '%s\n' "$out" | grep -qE '^work@example.com +2 +2 +12 ' \
  && ok "usage after the switch goes to the TO account, subagent transcripts included" \
  || bad "post-switch attribution wrong, or subagent transcripts missed" "$out"
bash "$SCRIPT" usage --days x >/dev/null 2>&1; [ $? -eq 1 ] && ok "usage rejects a non-numeric --days" || bad "usage accepted --days x"
rm -rf "$T"

# 11 — INJECTION. `security -i` re-tokenizes its line, quotes included, and a second -s wins:
# measured on a throwaway keychain, the email  a@b" -s "evil  wrote an item named "evil". The
# stub tokenizes with shlex, so an unguarded script reproduces the breakout here too.
new_env; seed_live home@example.com
crafted='a@b.com" -s "evil'
bash "$SCRIPT" add "$crafted" >/dev/null 2>&1; rc=$?
[ $rc -eq 1 ] && [ -z "$(kc_get evil)" ] \
  && ok "add rejects an email carrying a quote, and writes no foreign item" || bad "add accepted a crafted email" "rc=$rc"
bash "$SCRIPT" use "$crafted" --no-chrome >/dev/null 2>&1; rc=$?
[ $rc -eq 1 ] && [ -z "$(kc_get evil)" ] \
  && ok "use rejects a crafted email argument" || bad "use accepted a crafted email" "rc=$rc"
printf 'bad\t%s\n' "$crafted" >> "$HOME/.config/claude-acct/accounts"
bash "$SCRIPT" use bad --no-chrome >/dev/null 2>&1; rc=$?
[ $rc -eq 1 ] && [ -z "$(kc_get evil)" ] \
  && ok "a crafted row in the accounts file is rejected at alias resolution" || bad "crafted accounts row reached the keychain" "rc=$rc"
# The identity names the crafted address too, so the identity cross-check passes and the run
# reaches park_as's valid_email — the guard this case exists for.
export STUB_STATUS_EMAIL="$crafted"
jq --arg e "$crafted" '.oauthAccount.emailAddress = $e' "$CCJ" > "$CCJ.x" && mv "$CCJ.x" "$CCJ"
out=$(bash "$SCRIPT" save 2>&1); rc=$?
unset STUB_STATUS_EMAIL
[ $rc -eq 2 ] && [ -z "$(kc_get evil)" ] && case "$out" in *"not a plain email address"*) true ;; *) false ;; esac \
  && ok "a crafted email reported BY claude is refused as a slot name" || bad "save trusted a crafted live email" "rc=$rc $out"
rm -rf "$T"

# 12 — one save/add/use at a time; the lock carries its owner from the instant it exists
LOCK_PATH() { printf '%s' "$HOME/.local/state/claude-acct/lock"; }
new_env; seed_live home@example.com; seed_slot work@example.com
mkdir -p "$HOME/.local/state/claude-acct"; ln -s "$$" "$(LOCK_PATH)"
bash "$SCRIPT" use work --no-chrome >/dev/null 2>&1; rc=$?
[ $rc -eq 2 ] && [ "$(kc_get "$STUB_LIVE" .claudeAiOauth.accessToken)" = "TOK-home@example.com" ] \
  && ok "a live lock holder blocks a second switch (exit 2, nothing changed)" || bad "switch ran under a held lock" "rc=$rc"
bash "$SCRIPT" save >/dev/null 2>&1; rc=$?
[ $rc -eq 2 ] && ok "save takes the lock too" || bad "save ran under a held lock" "rc=$rc"
rm -f "$(LOCK_PATH)"; ln -s 99999999 "$(LOCK_PATH)"
bash "$SCRIPT" use work --no-chrome >/dev/null 2>&1; rc=$?
[ $rc -eq 0 ] && [ ! -L "$(LOCK_PATH)" ] && [ ! -e "$(LOCK_PATH)" ] \
  && ok "a stale lock is taken over, and released on exit" || bad "stale lock not recovered or not released" "rc=$rc"
[ "$(stat -f %Lp "$HOME/.local/state/claude-acct/switches.jsonl" 2>/dev/null)" = "600" ] \
  && ok "the switch log is 0600" || bad "switch log permissions" "$(stat -f %Lp "$HOME/.local/state/claude-acct/switches.jsonl" 2>/dev/null)"
rm -rf "$T"
# a lock left by the pre-identity script (a directory holding a pid file)
new_env; seed_live home@example.com; seed_slot work@example.com
mkdir -p "$(LOCK_PATH)"; printf '%s\n' "$$" > "$(LOCK_PATH)/pid"
bash "$SCRIPT" use work --no-chrome >/dev/null 2>&1; rc=$?
[ $rc -eq 2 ] && ok "a live pre-identity directory lock is honored" || bad "legacy lock ignored" "rc=$rc"
printf '99999999\n' > "$(LOCK_PATH)/pid"
bash "$SCRIPT" use work --no-chrome >/dev/null 2>&1; rc=$?
[ $rc -eq 0 ] && [ ! -e "$(LOCK_PATH)" ] && ok "a stale pre-identity directory lock is taken over" || bad "legacy stale lock not recovered" "rc=$rc"
rm -rf "$T"
# the owner pid exists the instant the lock does: read it while a run is mid-flight
new_env; seed_live home@example.com; seed_slot work@example.com
export STUB_STATUS_SCRIPT="$T/status-script"; printf 'ok' > "$STUB_STATUS_SCRIPT"
cat > "$T/bin/claude-wrap" <<'SH'
#!/bin/bash
[ -L "$HOME/.local/state/claude-acct/lock" ] && readlink "$HOME/.local/state/claude-acct/lock" > "$HOME/lock-seen"
exec "$(dirname "$0")/claude.real" "$@"
SH
mv "$T/bin/claude" "$T/bin/claude.real"; mv "$T/bin/claude-wrap" "$T/bin/claude"; chmod +x "$T/bin/claude"
bash "$SCRIPT" use work --no-chrome >/dev/null 2>&1 &
pid=$!; wait "$pid"
unset STUB_STATUS_SCRIPT
[ "$(cat "$HOME/lock-seen" 2>/dev/null)" = "$pid" ] \
  && ok "the lock names its owner pid while the run holds it" || bad "lock had no owner pid mid-run" "$(cat "$HOME/lock-seen" 2>/dev/null) vs $pid"
rm -rf "$T"

# 13 — a transient status failure after the write is retried, not read as a failed switch
# Call 1 is the pre-switch read, call 2 the re-check after reading the live records, call 3 the
# first post-write read — which flakes once.
new_env; seed_live home@example.com; seed_slot work@example.com
export STUB_STATUS_SCRIPT="$T/status-script"; printf 'ok ok fail' > "$STUB_STATUS_SCRIPT"
bash "$SCRIPT" use work --no-chrome >/dev/null 2>&1; rc=$?
[ $rc -eq 0 ] && [ "$(ccj_email)" = "work@example.com" ] \
  && ok "one failed status read after the write is retried, and the switch stands" \
  || bad "a transient status failure rolled back a good switch" "rc=$rc"
rm -rf "$T"
new_env; seed_live home@example.com; seed_slot work@example.com
export STUB_STATUS_SCRIPT="$T/status-script"; printf 'ok ok fail fail fail' > "$STUB_STATUS_SCRIPT"
bash "$SCRIPT" use work --no-chrome >/dev/null 2>&1; rc=$?
unset STUB_STATUS_SCRIPT
[ $rc -eq 3 ] && [ "$(kc_get "$STUB_LIVE" .claudeAiOauth.accessToken)" = "TOK-home@example.com" ] \
  && [ "$(ccj_email)" = "home@example.com" ] \
  && ok "a switch that can never be confirmed is still rolled back (exit 3)" \
  || bad "an unconfirmable switch was left in place" "rc=$rc"
rm -rf "$T"

# 14 — the account changes between the status read and the records read: refuse, change nothing
new_env; seed_live home@example.com; seed_slot work@example.com
export STUB_STATUS_SCRIPT="$T/status-script"; printf 'ok as:other@example.com' > "$STUB_STATUS_SCRIPT"
snap=$(snapshot)
bash "$SCRIPT" use work --no-chrome >/dev/null 2>&1; rc=$?
unset STUB_STATUS_SCRIPT
[ $rc -eq 2 ] && [ "$(snapshot)" = "$snap" ] \
  && ok "a live account that changes mid-read is refused before any write" \
  || bad "a token was filed or switched under a stale account name" "rc=$rc"
rm -rf "$T"

# 15 — a slot write that does not land is put back (or left absent), and exit 2 says which
new_env; seed_live home@example.com; seed_slot home@example.com
prev=$(kc_get "claude-acct/home@example.com")
export STUB_FAIL_WRITE="claude-acct/home@example.com"
out=$(bash "$SCRIPT" save 2>&1); rc=$?
unset STUB_FAIL_WRITE
[ $rc -eq 2 ] && [ "$(kc_get "claude-acct/home@example.com")" = "$prev" ] \
  && case "$out" in *"previous value is intact"*) true ;; *) false ;; esac \
  && ok "a failed slot write keeps the previous slot and says so" || bad "slot write failure handling" "rc=$rc $out"
rm -rf "$T"
new_env; seed_live home@example.com
export STUB_CORRUPT_WRITE="claude-acct/home@example.com"
out=$(bash "$SCRIPT" save 2>&1); rc=$?
unset STUB_CORRUPT_WRITE
[ $rc -eq 2 ] && [ -z "$(kc_get "claude-acct/home@example.com")" ] \
  && case "$out" in *"no slot was left behind"*) true ;; *) false ;; esac \
  && ok "a damaged first write of a slot is removed, not left half-written" || bad "damaged new slot left behind" "rc=$rc $out"
rm -rf "$T"
# 15b — save parks the identity next to the token
new_env; seed_live home@example.com
bash "$SCRIPT" save >/dev/null 2>&1; rc=$?
[ $rc -eq 0 ] && [ "$(kc_get "claude-acct/home@example.com" .oauthAccount.accountUuid)" = "uuid-home@example.com" ] \
  && ok "save parks the identity next to the token" || bad "save did not park the identity" "rc=$rc"
rm -rf "$T"
# 16 — a caller with no CLAUDE_CONFIG_DIR and no USER (a LaunchAgent, `env -i`) on a stock install
# still gets the account: the script hands `id -un` to the `claude` it runs, and both resolve the
# unsuffixed item and ~/.claude.json
new_env
USER="$(id -un)"; export USER; unset CLAUDE_CONFIG_DIR
export STUB_LIVE="Claude Code-credentials" CCJ="$HOME/.claude.json"
seed_live home@example.com
out=$(env -u CLAUDE_CONFIG_DIR -u USER bash "$SCRIPT" whoami 2>&1); rc=$?
[ $rc -eq 0 ] && [ "$out" = "home@example.com" ] \
  && ok "whoami with CLAUDE_CONFIG_DIR and USER unset reads the default config's account" \
  || bad "whoami under an empty environment" "rc=$rc $out"
rm -rf "$T"
# 17 — "logged in, no account named" is not "not logged in": no command tells that person to log in
new_env; seed_live home@example.com; export STUB_STATUS_MODE=noemail
for sub in whoami save; do
  out=$(bash "$SCRIPT" "$sub" 2>&1); rc=$?
  [ $rc -eq 2 ] && case "$out" in *"do not log in again"*) true ;; *) false ;; esac \
    && case "$out" in *"run: claude auth login"*) false ;; *) true ;; esac \
    && ok "$sub with a nameless live login says the lookup failed, not 'log in'" \
    || bad "$sub misreports a nameless live login" "rc=$rc $out"
done
before=$(snapshot)
out=$(bash "$SCRIPT" add work@example.com 2>&1); rc=$?
[ $rc -eq 2 ] && [ "$(snapshot)" = "$before" ] && [ ! -s "$STUB_OPEN_LOG" ] \
  && case "$out" in *"refusing to log in over a live token"*) true ;; *) false ;; esac \
  && ok "add refuses to log in over a live token it could not save, nothing changed" \
  || bad "add logged in over an unparked live token" "rc=$rc $out"
out=$(bash "$SCRIPT" list 2>&1 >/dev/null)
case "$out" in *"no account is marked live"*) ok "list notes a nameless live login on stderr" ;;
  *) bad "list is silent about a nameless live login" "$out" ;; esac
export STUB_STATUS_MODE=raw
out=$(bash "$SCRIPT" whoami 2>&1); rc=$?
[ $rc -eq 2 ] && case "$out" in *"could not ask claude auth status"*) true ;; *) false ;; esac \
  && ok "whoami when the CLI prints no JSON says it could not ask" || bad "whoami on a failed CLI" "rc=$rc $out"
before=$(snapshot)
out=$(bash "$SCRIPT" add work@example.com 2>&1); rc=$?
[ $rc -eq 2 ] && [ "$(snapshot)" = "$before" ] && [ ! -s "$STUB_OPEN_LOG" ] \
  && case "$out" in *"could not ask"*"refusing to log in"*) true ;; *) false ;; esac \
  && ok "add refuses when the CLI could not be asked, nothing changed" || bad "add when the CLI could not be asked" "rc=$rc $out"
export STUB_STATUS_MODE=object
out=$(bash "$SCRIPT" whoami 2>&1); rc=$?
before=$(snapshot)
out2=$(bash "$SCRIPT" add work@example.com 2>&1); rc2=$?
[ $rc -eq 2 ] && case "$out" in *"could not ask"*) true ;; *) false ;; esac \
  && [ $rc2 -eq 2 ] && [ "$(snapshot)" = "$before" ] \
  && ok "an object without loggedIn is 'could not ask', not 'logged out'" || bad "an object without loggedIn" "rc=$rc $out | rc2=$rc2 $out2"
export STUB_STATUS_MODE=noemail
before=$(snapshot)
out=$(bash "$SCRIPT" use work --no-chrome 2>&1); rc=$?
[ $rc -eq 2 ] && [ "$(snapshot)" = "$before" ] \
  && case "$out" in *"do not log in again"*"cannot tell which slot"*) true ;; *) false ;; esac \
  && ok "use with a nameless live login refuses and changes nothing" || bad "use with a nameless live login" "rc=$rc $out"
unset STUB_STATUS_MODE
rm -rf "$T"
# 17a — no account signed in under the config dir: the CLI still says loggedIn (an account-less
# token). That is "log in", and add proceeds: there is no account token to lose
new_env; export STUB_STATUS_MODE=bare-token
out=$(bash "$SCRIPT" whoami 2>&1); rc=$?
[ $rc -eq 2 ] && case "$out" in *"no claude.ai account is signed in"*"run: claude auth login"*) true ;; *) false ;; esac \
  && ok "whoami with only an account-less token says to log in" || bad "whoami with an account-less token" "rc=$rc $out"
out=$(bash "$SCRIPT" add other@example.com 2>&1); rc=$?
[ $rc -eq 0 ] && [ "$(kc_get "claude-acct/other@example.com" .oauthAccount.emailAddress)" = "other@example.com" ] \
  && ok "add over an account-less token logs in and saves" || bad "add over an account-less token" "rc=$rc $out"
unset STUB_STATUS_MODE
rm -rf "$T"
# 17b — logged out is still "log in", and add still proceeds from there
new_env
out=$(bash "$SCRIPT" whoami 2>&1); rc=$?
[ $rc -eq 2 ] && case "$out" in *"not logged in — run: claude auth login"*) true ;; *) false ;; esac \
  && ok "whoami when logged out says to log in" || bad "whoami when logged out" "rc=$rc $out"
out=$(bash "$SCRIPT" add other@example.com 2>&1); rc=$?
[ $rc -eq 0 ] && [ "$(kc_get "claude-acct/other@example.com" .oauthAccount.emailAddress)" = "other@example.com" ] \
  && ok "add from a logged-out state logs in and saves" || bad "add from logged out" "rc=$rc $out"
rm -rf "$T"
# 18 — no USER and no user name from id: refuse, never read keychain items under an empty account
new_env; seed_live home@example.com
printf '#!/bin/bash\nexit 0\n' > "$T/bin/id"; chmod +x "$T/bin/id"
out=$(env -u USER bash "$SCRIPT" whoami 2>&1); rc=$?
[ $rc -eq 2 ] && case "$out" in *"cannot pick the keychain account"*) true ;; *) false ;; esac \
  && ok "an empty keychain account is refused" || bad "an empty keychain account was used" "rc=$rc $out"
rm -rf "$T"
# 19 — limits: one line per known account from latest/<email>.json; never 0% for no data
new_env; seed_live home@example.com
L="$T/limits/latest"; mkdir -p "$L"; export CLAUDE_ACCT_LIMITS_DIR="$T/limits"
mkdir -p "$HOME/.local/state/claude-acct"
printf '%s\n' '{"ts":"2026-11-01T00:00:00Z","from":"ops@example.com","to":"home@example.com"}' \
  '{"ts":"2026-11-02T00:00:00Z","from":"home@example.com","to":"fund@example.com"}' \
  > "$HOME/.local/state/claude-acct/switches.jsonl"
now=$(date +%s); past=$((now - 3600)); future=$((now + 86400))
cap=$(date -u -r $((now - 120)) +%Y-%m-%dT%H:%M:%SZ)
printf '{"captured_at":"%s","email":"home@example.com","seven_day_pct":8,"seven_day_resets_at":%s,"five_hour_pct":12,"five_hour_resets_at":%s}\n' "$cap" "$future" "$future" > "$L/home@example.com.json"
printf '{"captured_at":"%s","email":"ops@example.com","seven_day_pct":89,"seven_day_resets_at":%s}\n' "$cap" "$past" > "$L/ops@example.com.json"
echo "2026-11-03T09:00:00Z" > "$L/.since"
out=$(bash "$SCRIPT" limits 2>&1); rc=$?
[ $rc -eq 0 ] && ok "limits exits 0" || bad "limits exit" "rc=$rc $out"
case "$out" in *"* home@example.com"*"8% of 7-day used, resets"*"5-hour 12%"*"reading 2m old"*) ok "limits shows the live account's percent, reset, 5-hour, and age" ;;
  *) bad "live account line wrong" "$out" ;; esac
case "$out" in *"ops@example.com"*"7-day window reset"*"89% before it"*) ok "limits says a passed reset instead of showing a stale percent" ;;
  *) bad "past reset not reported as reset" "$out" ;; esac
case "$out" in *"fund@example.com"*"no reading since"*) ok "limits says no reading, not 0%, for an account with no file" ;;
  *) bad "account with no reading misreported" "$out" ;; esac
case "$out" in *"fund@example.com"*" 0%"*) bad "an account with no data printed as 0%" "$out" ;; *) ok "no account without data prints 0%" ;; esac
rm -r "$L"
out=$(bash "$SCRIPT" limits 2>&1)
case "$out" in *"no readings recorded yet"*"none kept yet"*) ok "limits with no latest dir says nothing is kept yet" ;;
  *) bad "missing latest dir misreported" "$out" ;; esac
out=$(bash "$SCRIPT" limits extra 2>&1); rc=$?
[ $rc -eq 1 ] && ok "limits refuses arguments" || bad "limits took an argument" "rc=$rc $out"
unset CLAUDE_ACCT_LIMITS_DIR
rm -rf "$T"

# 16 — CLAUDE_CONFIG_DIR unset (a stock install): the Keychain service has no hash suffix and the
#      identity lives in ~/.claude.json, as the CLI binary resolves them
new_env; unset CLAUDE_CONFIG_DIR
export STUB_LIVE="Claude Code-credentials" CCJ="$HOME/.claude.json"
seed_live home@example.com; seed_slot work@example.com
bash "$SCRIPT" use work --no-chrome >/dev/null 2>&1; rc=$?
[ $rc -eq 0 ] && [ "$(kc_get "Claude Code-credentials" .claudeAiOauth.accessToken)" = "TOK-work@example.com-slot" ] \
  && [ "$(ccj_email)" = "work@example.com" ] \
  && [ "$(jq -r 'keys[] | select(startswith("Claude Code-credentials-"))' "$STUB_KC")" = "" ] \
  && ok "unset CLAUDE_CONFIG_DIR: switches the unsuffixed item and ~/.claude.json" \
  || bad "the stock-install locations were not used" "rc=$rc ccj=$(ccj_email) items=$(jq -c keys "$STUB_KC")"
rm -rf "$T"

# 16b — CLAUDE_SECURESTORAGE_CONFIG_DIR="" overrides the Keychain half only: no suffix, while the
#       identity stays in $CLAUDE_CONFIG_DIR/.claude.json
new_env; export CLAUDE_SECURESTORAGE_CONFIG_DIR="" STUB_LIVE="Claude Code-credentials"
seed_live home@example.com; seed_slot work@example.com
bash "$SCRIPT" use work --no-chrome >/dev/null 2>&1; rc=$?
[ $rc -eq 0 ] && [ "$(kc_get "Claude Code-credentials" .claudeAiOauth.accessToken)" = "TOK-work@example.com-slot" ] \
  && [ "$(jq -r .oauthAccount.emailAddress "$CLAUDE_CONFIG_DIR/.claude.json")" = "work@example.com" ] \
  && ok "CLAUDE_SECURESTORAGE_CONFIG_DIR moves the Keychain item only" \
  || bad "the secure-storage override was not honored" "rc=$rc"
unset CLAUDE_SECURESTORAGE_CONFIG_DIR
rm -rf "$T"

# 20 — record-limits: a statusline payload becomes the newest reading for the account it was made on
new_env; seed_live home@example.com
export CLAUDE_ACCT_LIMITS_DIR="$T/limits"; L="$T/limits/latest"
now=$(date +%s); r1=$((now + 86400)); r2=$((now + 172800))
pay() {  # $1 7-day pct (or "none")  $2 7-day reset  [$3 5-hour pct]
  local fh=""; [ -n "${3:-}" ] && fh=",\"five_hour\":{\"used_percentage\":$3,\"resets_at\":$2}"
  if [ "$1" = none ]; then printf '{"version":"2.1.318","rate_limits":{%s}}' "${fh#,}"
  else printf '{"version":"2.1.318","rate_limits":{"seven_day":{"used_percentage":%s,"resets_at":%s}%s}}' "$1" "$2" "$fh"; fi
}
out=$(pay 41 "$r1" 7 | bash "$SCRIPT" record-limits 2>&1); rc=$?
[ $rc -eq 0 ] && [ -z "$out" ] && [ "$(jq -r .seven_day_pct "$L/home@example.com.json" 2>/dev/null)" = 41 ] \
  && [ "$(jq -r .five_hour_pct "$L/home@example.com.json")" = 7 ] && [ -s "$L/.since" ] \
  && ok "record-limits keeps the live account's reading, silently" \
  || bad "record-limits did not keep the live reading" "rc=$rc out=$out $(cat "$L/home@example.com.json" 2>&1)"
case "$(bash "$SCRIPT" limits 2>&1)" in *"* home@example.com"*"41% of 7-day used"*"5-hour 7%"*) ok "limits reads what record-limits kept" ;;
  *) bad "limits did not show the recorded reading" "$(bash "$SCRIPT" limits 2>&1)" ;; esac
pay 43 "$r1" | bash "$SCRIPT" record-limits
[ "$(jq -r .seven_day_pct "$L/home@example.com.json")" = 43 ] && [ "$(jq -r .five_hour_pct "$L/home@example.com.json")" = null ] \
  && case "$(bash "$SCRIPT" limits 2>&1)" in *"5-hour"*) false ;; *) true ;; esac \
  && ok "a reading with no 5-hour window (Ultra) is kept and shows no 5-hour figure" \
  || bad "a 5-hour-less reading was mishandled" "$(cat "$L/home@example.com.json")"
printf '{"captured_at":"2026-11-05T00:00:00Z","email":"work@example.com","seven_day_pct":60,"seven_day_resets_at":%s}\n' "$r2" > "$L/work@example.com.json"
pay 61 "$r2" | bash "$SCRIPT" record-limits
[ "$(jq -r .seven_day_pct "$L/work@example.com.json")" = 61 ] && [ "$(jq -r .seven_day_pct "$L/home@example.com.json")" = 43 ] \
  && ok "a reading on another account's reset window is filed under that account" \
  || bad "reset-window attribution failed" "work=$(jq -c . "$L/work@example.com.json") home=$(jq -c . "$L/home@example.com.json")"
before=$(cat "$L"/*.json)
for junk in '{"version":"2.1.318"}' 'not json at all' '' "$(pay none "$r1" 9)"; do
  out=$(printf '%s' "$junk" | bash "$SCRIPT" record-limits 2>&1); rc=$?
  [ $rc -eq 0 ] && [ -z "$out" ] || bad "record-limits was not silent on: $junk" "rc=$rc $out"
done
[ "$(cat "$L"/*.json)" = "$before" ] && ok "no rate_limits, garbage, or a 7-day-less payload leaves every reading alone" \
  || bad "a payload with no 7-day reading changed a file" "$(cat "$L"/*.json)"
unset CLAUDE_ACCT_LIMITS_DIR
rm -rf "$T"

printf '\n  %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
