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
        STUB_CCJ_TOUCH CLAUDE_ACCT_CCJ_LOCK_WAIT BROWSER CLAUDE_SECURESTORAGE_CONFIG_DIR \
        STUB_REFRESH_ON_READ STUB_MCP_REFRESH_ON_READ STUB_REFRESH_AFTER_ADD STUB_MCP_REFRESH_AFTER_ADD \
        STUB_FAIL_WRITE_FROM STUB_REFRESH_ON_STATUS_FROM STUB_MCP_REFRESH_ON_STATUS_FROM STUB_FAIL_READ_AT \
        STUB_NOW CLAUDE_ACCT_STATE_DIR
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
def bump(name):  # a per-test counter file next to the keychain: returns the new count
    p = db + "." + name
    n = (int(open(p).read()) if os.path.exists(p) else 0) + 1
    open(p, "w").write(str(n)); return n
def mutate(d, key, how):  # a running session rewriting the live item: its token, or one MCP login
    try: v = json.loads(d[key])
    except Exception: return
    if how == "token": v["claudeAiOauth"]["accessToken"] = os.environ.get("STUB_MUTATE_TOKEN", "refreshed-by-test")
    else:   # counts up, so a second MCP refresh changes the bytes again
        m = v.setdefault("mcpOAuth", {}); m["test"] = {"refreshed": m.get("test", {}).get("refreshed", 0) + 1}
    d[key] = json.dumps(v); save(d)
def at(var, n):  # the hook names this read or write: one index, or a comma list of them
    return str(n) in os.environ.get(var, "").split(",")
def run(a):
    cmd, o = a[0], opts(a[1:])
    key = f'{o.get("-s")}|{o.get("-a")}'
    live = o.get("-s") == os.environ["STUB_LIVE"]
    d = load()
    if cmd == "find-generic-password":
        if key not in d: return 44
        if live:
            n = bump("live-reads")
            if at("STUB_FAIL_READ_AT", n): return 36            # a keychain read that fails, not "absent"
            if at("STUB_REFRESH_ON_READ", n):
                os.environ["STUB_MUTATE_TOKEN"] = "refreshed-on-read"; mutate(d, key, "token"); d = load()
            if at("STUB_MCP_REFRESH_ON_READ", n): mutate(d, key, "mcp"); d = load()
        if "-w" in o: print(d[key])
        return 0
    if cmd == "add-generic-password":
        if key in d and "-U" not in o: return 45
        val = bytes.fromhex(o["-X"]).decode() if "-X" in o else o.get("-w", "")
        if live: bump("live-write-attempts")        # counted even when the write silently fails
        if os.environ.get("STUB_FAIL_WRITE") == o.get("-s"): return 0   # silent non-persist
        if os.environ.get("STUB_CORRUPT_WRITE") == o.get("-s"): val = val[:-1]  # lands damaged
        n = bump("live-writes") if live else 0
        if live and os.environ.get("STUB_FAIL_WRITE_FROM") and n >= int(os.environ["STUB_FAIL_WRITE_FROM"]):
            return 0                                                      # silent non-persist from the n-th
        d[key] = val; save(d)
        # A running session refreshing the live item between the write and its read-back.
        # The value names the live write it follows (1 = use's own write, 2 = the rollback's).
        if live and at("STUB_REFRESH_AFTER_ADD", n):
            os.environ["STUB_MUTATE_TOKEN"] = "refreshed-in-gap"; mutate(d, key, "token")
        if live and at("STUB_MCP_REFRESH_AFTER_ADD", n): mutate(d, key, "mcp")
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
    # From the n-th status call on, a running session rewrites the live item (its token, or only
    # an MCP login): the window after use's write, while it waits for the account to confirm.
    cp = db + ".status-calls"
    calls = (int(open(cp).read()) if os.path.exists(cp) else 0) + 1
    open(cp, "w").write(str(calls))
    for var, how in (("STUB_REFRESH_ON_STATUS_FROM", "token"), ("STUB_MCP_REFRESH_ON_STATUS_FROM", "mcp")):
        if os.environ.get(var) and calls >= int(os.environ[var]) and live in d:
            v = json.loads(d[live])
            if how == "token": v["claudeAiOauth"]["accessToken"] = "refreshed-by-test"
            else: v.setdefault("mcpOAuth", {})["test"] = {"refreshed": 1}
            d[live] = json.dumps(v); json.dump(d, open(db, "w"))
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
  # A fixed clock for `date +%s` only when STUB_NOW is set; every other call, and every case that
  # leaves STUB_NOW unset, runs the real date.
  printf '#!/bin/bash\nif [ -n "${STUB_NOW:-}" ] && [ "$#" -eq 1 ] && [ "$1" = "+%%s" ]; then printf "%%s\\n" "$STUB_NOW"; exit 0; fi\nexec /bin/date "$@"\n' > "$T/bin/date"
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
printf '%s\n' '{"ts":"2026-11-01T00:00:00Z","from":"ops.longest@example.test","to":"home@example.com"}' \
  '{"ts":"2026-11-02T00:00:00Z","from":"home@example.com","to":"fund@example.com"}' \
  > "$HOME/.local/state/claude-acct/switches.jsonl"
now=$(date +%s); past=$((now - 3600)); future=$((now + 86400))
cap=$(date -u -r $((now - 120)) +%Y-%m-%dT%H:%M:%SZ)
printf '{"captured_at":"%s","email":"home@example.com","seven_day_pct":8,"seven_day_resets_at":%s,"five_hour_pct":12,"five_hour_resets_at":%s}\n' "$cap" "$future" "$future" > "$L/home@example.com.json"
printf '{"captured_at":"%s","email":"ops.longest@example.test","seven_day_pct":89,"seven_day_resets_at":%s}\n' "$cap" "$past" > "$L/ops.longest@example.test.json"
echo "2026-11-03T09:00:00Z" > "$L/.since"
# a table of quota LEFT that fits a narrow pane (46 columns with these emails).
line_of() { printf '%s\n' "$out" | grep -F -- "$1" | head -1; }
fits46() { printf '%s\n' "$out" | awk '{ if (length > 46) bad=1 } END { exit bad }'; }
out=$(bash "$SCRIPT" limits 2>&1); rc=$?
[ $rc -eq 0 ] && ok "limits exits 0" || bad "limits exit" "rc=$rc $out"
fits46 && ok "limits: every line fits 46 columns" || bad "limits: a line is wider than 46" "$out"
case "$(printf '%s\n' "$out" | head -1)" in "  ACCOUNT"*" LEFT  RESETS") ok "limits: header names ACCOUNT, LEFT, RESETS" ;; *) bad "limits header" "$out" ;; esac
row=$(line_of "* home@example.com")
printf '%s\n' "$row" | grep -Eq '^\* home@example\.com +92%  [A-Z][a-z][a-z] [0-9]{1,2} [0-9]{1,2}:[0-9][0-9][ap]$' \
  && ok "limits: the live account shows 92% left and a short reset" || bad "live account row" "$row"
row=$(line_of "ops.longest@example.test")
printf '%s\n' "$row" | grep -Eq ' +-  was [0-9]{1,2} [0-9]{1,2}:[0-9][0-9][ap]$' \
  && ok "limits: a passed reset shows - and was <when>, not a stale percent" || bad "past reset row" "$row"
row=$(line_of "fund@example.com")
printf '%s\n' "$row" | grep -Eq ' +-  no reading$' && ok "limits: an account with no file reads - no reading" || bad "no-reading row" "$row"
case "$row" in *"0%"*) bad "an account with no data printed as 0%" "$row" ;; *) ok "no account without data prints 0%" ;; esac
case "$out" in *"7-day quota · times "*) ok "limits: the footer names the zone once" ;; *) bad "zone footer missing" "$out" ;; esac
# the statusline payload carries no per-model weekly cap, so the footer says so.
case "$(printf '%s\n' "$out" | tr '\n' ' ' | tr -s ' ')" in
  *"Per-model weekly caps (Fable) are not in the statusline payload"*) ok "limits: the footer says per-model caps are not shown" ;;
  *) bad "per-model cap caveat missing from the footer" "$out" ;; esac
case "$out" in *"5h: home@example.com 12%"*) ok "limits: an unexpired 5-hour reading is on a footer line" ;; *) bad "5h footer missing" "$out" ;; esac
case "$out" in *"(reading"*|*"kept since"*|*"stale (>1h)"*) bad "limits printed a per-row age, the since footer, or a stale line with no stale reading" "$out" ;; *) ok "limits: no per-row age, no since footer, no stale line when nothing is stale" ;; esac
# A reading older than an hour gets the stale footer; a fractional percent stays 4 wide.
old=$(date -u -r $((now - 10800)) +%Y-%m-%dT%H:%M:%SZ)
printf '{"captured_at":"%s","email":"fund@example.com","seven_day_pct":22.5,"seven_day_resets_at":%s}\n' "$old" "$future" > "$L/fund@example.com.json"
out=$(bash "$SCRIPT" limits 2>&1)
case "$out" in *"stale (>1h): fund@example.com 3h"*) ok "limits: a 3h-old reading is named on the stale footer" ;; *) bad "stale footer" "$out" ;; esac
row=$(line_of "fund@example.com ")
printf '%s\n' "$row" | grep -Eq ' 78%  ' && ok "limits: 22.5% used prints 78% left, 4 wide" || bad "fractional percent" "$row"
fits46 && ok "limits: still fits 46 with a stale footer" || bad "stale footer overflows" "$out"
# Many stale accounts: the footer wraps instead of overflowing.
mkdir -p "$HOME/.config/claude-acct"
printf 'a\tone@stale.example\nb\ttwo@stale.example\nc\tthree@stale.example\nd\tfour@stale.example\n' > "$HOME/.config/claude-acct/accounts"
for e in one two three four; do
  printf '{"captured_at":"%s","email":"%s@stale.example","seven_day_pct":10,"seven_day_resets_at":%s}\n' "$old" "$e" "$future" > "$L/$e@stale.example.json"
done
out=$(bash "$SCRIPT" limits 2>&1)
fits46 && case "$out" in *"four@stale.example 3h"*) true ;; *) false ;; esac \
  && ok "limits: a long stale footer wraps within 46" || bad "long stale footer" "$out"
# A 30+ character email widens the column; every row and the header stay aligned to it.
LONG=a.very.long.address@example.test
printf 'a\t%s\n' "$LONG" > "$HOME/.config/claude-acct/accounts"
out=$(bash "$SCRIPT" limits 2>&1)
# header = 2 + W + " LEFT  RESETS"; a row's LEFT value ends at column 2 + W + 5, under the header's LEFT.
endleft=$((2 + ${#LONG} + 5))
hdr=$(printf '%s\n' "$out" | head -1); row=$(line_of "fund@example.com ")
[ "${#hdr}" -eq $((2 + ${#LONG} + 13)) ] && [ "$(printf '%s' "$hdr" | cut -c$((endleft - 3))-$endleft)" = "LEFT" ] \
  && [ "$(printf '%s' "$row" | cut -c$((endleft - 2))-$endleft)" = "78%" ] \
  && ok "limits: a ${#LONG}-character email widens the column, header and rows aligned" || bad "long email alignment" "$(printf '%s\n' "$out" | awk '{print length": "$0}')"
rm -f "$HOME/.config/claude-acct/accounts"
rm -r "$L"
out=$(bash "$SCRIPT" limits 2>&1)
case "$out" in *"home@example.com"*"-  no reading"*) ok "limits with no latest dir reads no reading" ;;
  *) bad "missing latest dir misreported" "$out" ;; esac
# The widest RESETS (2-digit day and hour) on the 24-character email is exactly 46, pinned by
# fixed epochs under TZ=UTC rather than by whatever day the suite runs on.
mkdir -p "$L"
reading() {  # $1 email  $2 the JSON fields after captured_at
  printf '{"captured_at":"%s",%s}\n' "$cap" "$2" > "$L/$1.json"
}
reading ops.longest@example.test '"seven_day_pct":10,"seven_day_resets_at":4101057000'   # Tue 15 10:30p UTC
reading fund@example.com '"seven_day_pct":50,"seven_day_resets_at":1605222000'            # was 12 11:00p UTC
reading home@example.com '"seven_day_pct":130,"seven_day_resets_at":4101057000'
out=$(TZ=UTC bash "$SCRIPT" limits 2>&1)
row=$(line_of "ops.longest@example.test")
[ "$row" = "$(printf '  %-24s %4s  %s' ops.longest@example.test 90% 'Tue 15 10:30p')" ] && [ ${#row} -eq 46 ] \
  && ok "limits: the widest live row is exactly 46" || bad "widest live row" "${#row}: $row"
row=$(line_of "fund@example.com")
[ "$row" = "$(printf '  %-24s %4s  %s' fund@example.com - 'was 12 11:00p')" ] && [ ${#row} -eq 46 ] \
  && ok "limits: the widest passed-reset row is exactly 46" || bad "widest was row" "${#row}: $row"
row=$(line_of "home@example.com")
printf '%s\n' "$row" | grep -Eq ' 0%  Tue 15' && ok "limits: over 100% used clamps to 0% left" || bad "clamp high" "$row"
case "$out" in *"times UTC"*) ok "limits: the footer names the zone of the times shown" ;; *) bad "UTC footer" "$out" ;; esac
# Below 0% used clamps to 100%; no reset time reads unknown; a bad capture time is stale "?";
# a 5-hour reading is shown even when the 7-day one is missing.
reading home@example.com '"seven_day_pct":-5'
reading ops.longest@example.test '"seven_day_pct":10,"seven_day_resets_at":4101057000'
sed -i '' 's/"captured_at":"[^"]*"/"captured_at":"junk"/' "$L/ops.longest@example.test.json"
reading fund@example.com '"seven_day_pct":null,"five_hour_pct":30,"five_hour_resets_at":4101057000'
out=$(TZ=UTC bash "$SCRIPT" limits 2>&1)
row=$(line_of "home@example.com")
printf '%s\n' "$row" | grep -Eq '100%  unknown$' && ok "limits: below 0% used clamps to 100%, no reset reads unknown" || bad "clamp low / unknown" "$row"
case "$out" in *"stale (>1h): ops.longest@example.test ?"*) ok "limits: an unreadable capture time is listed stale with age ?" ;; *) bad "bad captured_at read as fresh" "$out" ;; esac
row=$(line_of "fund@example.com")
printf '%s\n' "$row" | grep -Eq ' -  no reading$' && case "$out" in *"5h: fund@example.com 30%"*) true ;; *) false ;; esac \
  && ok "limits: a 5-hour reading shows without a 7-day one" || bad "5h without 7-day" "$out"
fits46 && ok "limits: clamp, unknown, and footers fit 46" || bad "overflow" "$out"
# A malformed file costs its own row: not JSON, a string percent, NaN, a non-object.
printf 'not json\n' > "$L/home@example.com.json"
reading ops.longest@example.test '"seven_day_pct":"x","seven_day_resets_at":4101057000'
reading fund@example.com '"seven_day_pct":NaN,"seven_day_resets_at":4101057000'
out=$(TZ=UTC bash "$SCRIPT" limits 2>&1); rc=$?
n=$(printf '%s\n' "$out" | grep -cE ' -  unreadable$' || true)
[ $rc -eq 0 ] && [ "$n" -eq 3 ] && case "$out" in *"7-day quota · times"*"unreadable reading: "*) true ;; *) false ;; esac \
  && ok "limits: malformed readings each read unreadable, and the table still finishes" || bad "malformed readings" "rc=$rc n=$n $out"
printf '[1]\n' > "$L/fund@example.com.json"
out=$(TZ=UTC bash "$SCRIPT" limits 2>&1)
printf '%s\n' "$(line_of "fund@example.com")" | grep -Eq ' -  unreadable$' && ok "limits: a non-object reading reads unreadable" || bad "non-object reading" "$out"
# Times on both sides of a DST change name both zones.
rm -f "$L"/*.json
reading ops.longest@example.test '"seven_day_pct":10,"seven_day_resets_at":4087816200'  # July: MDT
reading fund@example.com '"seven_day_pct":50,"seven_day_resets_at":1605222000'          # November: MST
out=$(TZ=America/Denver bash "$SCRIPT" limits 2>&1)
case "$out" in *"times MDT/MST"*|*"times MST/MDT"*) ok "limits: times in two zones name both" ;; *) bad "DST zones" "$out" ;; esac
out=$(bash "$SCRIPT" limits extra 2>&1); rc=$?
[ $rc -eq 1 ] && ok "limits refuses arguments" || bad "limits took an argument" "rc=$rc $out"
rm -rf "$T"
# No known accounts (no accounts file, no switch log, nothing live): the message alone, within 46.
new_env; export CLAUDE_ACCT_LIMITS_DIR="$T/limits"; rm -f "$HOME/.config/claude-acct/accounts"
out=$(bash "$SCRIPT" limits 2>&1); rc=$?
[ $rc -eq 0 ] && case "$out" in "no accounts known yet"*) true ;; *) false ;; esac && fits46 \
  && ok "limits with no known accounts says so within 46" || bad "no-accounts message" "rc=$rc $out"
unset CLAUDE_ACCT_LIMITS_DIR
rm -rf "$T"

# ── list --json, use --expect-from, the re-reads, live_class, where, chrome ──────
acct_file() { printf '%b' "$1" > "$HOME/.config/claude-acct/accounts"; }
# A slot carrying named secret values, so a no-credential check has something it could leak.
seed_secret_slot() {  # $1 email  $2 alias
  python3 - "$1" "$2" <<'PY'
import json, os, sys, time
d = json.load(open(os.environ["STUB_KC"]))
d["claude-acct/" + sys.argv[1] + "|" + os.environ["USER"]] = json.dumps({
  "claudeAiOauth": {"accessToken": "at-secret-" + sys.argv[2], "refreshToken": "rt-secret-" + sys.argv[2],
                    "refreshTokenExpiresAt": int((time.time() + 30 * 86400) * 1000)},
  "oauthAccount": {"emailAddress": sys.argv[1], "accountUuid": "uuid-" + sys.argv[1]}})
json.dump(d, open(os.environ["STUB_KC"], "w"))
PY
}
mcp_test_key() { kc_get "$STUB_LIVE" '.mcpOAuth.test.refreshed // empty'; }

# 20 — list --json: one object per account, fourth-column lastResort, nulls where nothing is known
new_env; seed_live alpha@x.test; seed_slot alpha@x.test; seed_slot beta@x.test
acct_file 'a\talpha@x.test\tProfile 1\tlastResort\nb\tbeta@x.test\nc\tgamma@x.test\t\tlastResort\n'
out=$(bash "$SCRIPT" list --json 2>/dev/null); rc=$?
[ $rc -eq 0 ] && printf '%s' "$out" | jq -e 'length==3 and .[0].email=="alpha@x.test" and .[0].last_resort==true
    and .[0].chrome_profile=="Profile 1" and .[0].live==true and .[0].saved==true and .[0].slot_ok==true
    and .[0].alias=="a" and .[1].alias=="b" and .[1].last_resort==false and .[1].live==false
    and .[2].chrome_profile==null and .[2].last_resort==true and .[2].saved==false and .[2].slot_ok==false
    and .[2].refresh_until==null and .[2].refresh_expires_in_days==null and .[2].slot_problem==null
    and (.[0]|has("refresh_expires_in_days"))' >/dev/null \
  && ok "list --json: one object per account, lastResort read positionally, nulls when unknown" \
  || bad "list --json shape" "rc=$rc $out"
rm -rf "$T"
# 20b — a fourth column that is not the literal lastResort is not last-resort
new_env; seed_live alpha@x.test
acct_file 'a\talpha@x.test\t\tlastresort\nb\tbeta@x.test\t\tyes\n'
out=$(bash "$SCRIPT" list --json 2>/dev/null)
printf '%s' "$out" | jq -e 'length==2 and all(.[]; .last_resort==false)' >/dev/null \
  && ok "list --json: only the literal lastResort counts" || bad "a non-literal fourth column read as lastResort" "$out"
rm -rf "$T"
# 20c — refresh-token expiry: 3.5 days out lists 3 days, a day past lists expired; a bad slot says why
new_env; seed_live alpha@x.test
acct_file 'a\talpha@x.test\nsoon\tsoon@x.test\nold\told@x.test\nmix\tmix@x.test\n'
seed_slot soon@x.test "" 3.5; seed_slot old@x.test "" -1; seed_slot mix@x.test acct:other@x.test 30
out=$(bash "$SCRIPT" list --json 2>/dev/null)
printf '%s' "$out" | jq -e '(.[] | select(.email=="soon@x.test")) as $s | (.[] | select(.email=="old@x.test")) as $o
    | (.[] | select(.email=="mix@x.test")) as $m
    | $s.refresh_expires_in_days==3 and $s.refresh_expired==false and ($s.refresh_until|test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$"))
    and $o.refresh_expired==true and $m.slot_ok==false and $m.saved==true
    and $m.slot_problem=="identity of '"'"'other@x.test'"'"'"' >/dev/null \
  && ok "list --json: expiry in days, expired, and the slot problem text" || bad "list --json expiry or slot problem" "$out"
rm -rf "$T"
# 20d — list --json prints no credential, from slots that carry named secrets
new_env; seed_live alpha@x.test; seed_secret_slot alpha@x.test a; seed_secret_slot beta@x.test b
acct_file 'a\talpha@x.test\nb\tbeta@x.test\n'
out=$(bash "$SCRIPT" list --json 2>&1)
case "$out" in *at-secret-*|*rt-secret-*|*TOK-*|*MCP-LINEAR-SECRET*) bad "list --json printed a credential" "$out" ;;
  *) printf '%s' "$out" | jq -e 'length==2' >/dev/null && ok "list --json prints no access or refresh token" \
       || bad "list --json did not list the seeded slots" "$out" ;; esac
rm -rf "$T"
# 20e — with no account live, list --json is still one valid array, every live false, exit 0
new_env
acct_file 'a\talpha@x.test\n'
out=$(bash "$SCRIPT" list --json 2>/dev/null); rc=$?
[ $rc -eq 0 ] && printf '%s' "$out" | jq -e 'type=="array" and length==1 and all(.[]; .live==false)' >/dev/null \
  && ok "list --json with no live account: valid array, nothing live, exit 0" || bad "list --json logged out" "rc=$rc $out"
rm -rf "$T"
# 20f — list refuses any argument other than one --json; plain list is unchanged (test 9)
new_env; seed_live home@example.com
out=$(bash "$SCRIPT" list --bogus 2>&1); rc=$?
[ $rc -eq 1 ] && case "$out" in *"usage: claude-acct.sh list [--json]"*) true ;; *) false ;; esac \
  && ok "list --bogus: exit 1 with the list usage line" || bad "list accepted an unknown argument" "rc=$rc $out"
bash "$SCRIPT" list --json --json >/dev/null 2>&1; rc=$?
[ $rc -eq 1 ] && ok "list --json --json: exit 1" || bad "list accepted --json twice" "rc=$rc"
bash "$SCRIPT" list >/dev/null 2>&1; rc=$?
[ $rc -eq 0 ] && ok "plain list still exits 0" || bad "plain list broke" "rc=$rc"
rm -rf "$T"

# 21 — use --expect-from: a mismatch is refused under the lock, nothing changes
new_env; seed_live home@example.com; seed_slot work@example.com
snap=$(snapshot)
out=$(bash "$SCRIPT" use work --no-chrome --expect-from gamma@x.test 2>&1); rc=$?
[ $rc -eq 2 ] && [ "$(snapshot)" = "$snap" ] && case "$out" in *expect*) true ;; *) false ;; esac \
  && ok "--expect-from naming another account: exit 2, nothing changed" || bad "--expect-from mismatch" "rc=$rc $out"
out=$(bash "$SCRIPT" use work --no-chrome --expect-from home@example.com 2>&1); rc=$?
[ $rc -eq 0 ] && [ "$(ccj_email)" = "work@example.com" ] \
  && [ "$(kc_get "$STUB_LIVE" .claudeAiOauth.accessToken)" = "TOK-work@example.com-slot" ] \
  && ok "--expect-from naming the live account: the switch runs" || bad "--expect-from match did not switch" "rc=$rc $out"
rm -rf "$T"
new_env; seed_live home@example.com; seed_slot work@example.com
snap=$(snapshot)
out=$(bash "$SCRIPT" use work --expect-from 2>&1); rc=$?
[ $rc -eq 1 ] && [ "$(snapshot)" = "$snap" ] && case "$out" in *"usage: claude-acct.sh use"*) true ;; *) false ;; esac \
  && ok "--expect-from with no value: exit 1 with the usage line, nothing changed" || bad "--expect-from missing value" "rc=$rc $out"
bash "$SCRIPT" use work --expect-from a@x.test --expect-from b@x.test >/dev/null 2>&1; rc=$?
[ $rc -eq 1 ] && [ "$(snapshot)" = "$snap" ] && ok "--expect-from twice: exit 1, nothing changed" || bad "--expect-from twice" "rc=$rc"
rm -rf "$T"

# 21b — use --not-after: checked under the lock, before the live account is read
new_env; seed_live home@example.com; seed_slot work@example.com
snap=$(snapshot)
past=$(( $(/bin/date +%s) - 3600 ))
out=$(bash "$SCRIPT" use work --no-chrome --not-after "$past" 2>&1); rc=$?
[ $rc -eq 2 ] && [ "$(snapshot)" = "$snap" ] && case "$out" in *"past --not-after $past; nothing was switched"*) true ;; *) false ;; esac \
  && ! grep -q add-generic-password "$STUB_ARGV_LOG" 2>/dev/null \
  && [ ! -e "$HOME/.local/state/claude-acct/lock" ] && [ ! -L "$HOME/.local/state/claude-acct/lock" ] \
  && ok "--not-after an hour ago: exit 2, no keychain write, the lock released" \
  || bad "--not-after in the past" "rc=$rc $out"
future=$(( $(/bin/date +%s) + 3600 ))
out=$(bash "$SCRIPT" use work --no-chrome --not-after "$future" 2>&1); rc=$?
[ $rc -eq 0 ] && [ "$(ccj_email)" = "work@example.com" ] \
  && [ "$(kc_get "$STUB_LIVE" .claudeAiOauth.accessToken)" = "TOK-work@example.com-slot" ] \
  && ok "--not-after an hour ahead: the switch lands as without the flag" || bad "--not-after in the future" "rc=$rc $out"
rm -rf "$T"
# The boundary on a fixed clock: the named second itself is admitted, one second earlier is not.
new_env; seed_live home@example.com; seed_slot work@example.com
export STUB_NOW=1700000000
snap=$(snapshot)
out=$(bash "$SCRIPT" use work --no-chrome --not-after 1699999999 2>&1); rc=$?
[ $rc -eq 2 ] && [ "$(snapshot)" = "$snap" ] && case "$out" in *"past --not-after 1699999999"*) true ;; *) false ;; esac \
  && ok "--not-after one second before now: refused (exit 2)" || bad "--not-after one second past" "rc=$rc $out"
out=$(bash "$SCRIPT" use work --no-chrome --not-after 1700000000 2>&1); rc=$?
[ $rc -eq 0 ] && [ "$(ccj_email)" = "work@example.com" ] \
  && ok "--not-after naming the current second: admitted" || bad "--not-after at the current second" "rc=$rc $out"
unset STUB_NOW
rm -rf "$T"
new_env; seed_live home@example.com; seed_slot work@example.com
snap=$(snapshot)
bash "$SCRIPT" use work --no-chrome --not-after 4102444800 --not-after 4102444800 >/dev/null 2>&1; rc=$?
[ $rc -eq 1 ] && [ "$(snapshot)" = "$snap" ] && ok "--not-after twice: exit 1, nothing changed" || bad "--not-after twice" "rc=$rc"
bash "$SCRIPT" use work --no-chrome --not-after soon >/dev/null 2>&1; rc=$?
[ $rc -eq 1 ] && [ "$(snapshot)" = "$snap" ] && ok "--not-after soon: exit 1, nothing changed" || bad "--not-after non-numeric" "rc=$rc"
bash "$SCRIPT" use work --no-chrome --not-after >/dev/null 2>&1; rc=$?
[ $rc -eq 1 ] && [ "$(snapshot)" = "$snap" ] && ok "--not-after with no value: exit 1, nothing changed" || bad "--not-after missing value" "rc=$rc"
rm -rf "$T"

# 22 — the live login refreshed between use's read and its write: abort, write nothing live
# Live-item reads in use: 1 read_live_as, 2 the re-read just before kc_write.
new_env; seed_live home@example.com; seed_slot work@example.com
ccj_before=$(jq -cS . "$CCJ")
export STUB_REFRESH_ON_READ=2
out=$(bash "$SCRIPT" use work --no-chrome 2>&1); rc=$?
unset STUB_REFRESH_ON_READ
[ $rc -eq 2 ] && case "$out" in *"live login changed"*) true ;; *) false ;; esac \
  && [ "$(kc_get "$STUB_LIVE" .claudeAiOauth.accessToken)" = "refreshed-on-read" ] \
  && [ "$(jq -cS . "$CCJ")" = "$ccj_before" ] \
  && ok "a refresh before the write aborts with exit 2; the refreshed login and .claude.json are untouched" \
  || bad "a changed live login was overwritten" "rc=$rc $out"
rm -rf "$T"

# 23 — after use's write lands, a session writes a token this run never saw: exit 4, rewrite nothing
new_env; seed_live home@example.com; seed_slot work@example.com
export STUB_STATUS_SCRIPT="$T/status-script"; printf 'ok ok fail fail fail' > "$STUB_STATUS_SCRIPT"
export STUB_REFRESH_ON_STATUS_FROM=3
out=$(bash "$SCRIPT" use work --no-chrome 2>&1); rc=$?
unset STUB_STATUS_SCRIPT STUB_REFRESH_ON_STATUS_FROM
[ $rc -eq 4 ] && [ "$(kc_get "$STUB_LIVE" .claudeAiOauth.accessToken)" = "refreshed-by-test" ] \
  && [ "$(ccj_email)" = "work@example.com" ] \
  && case "$out" in *"claude auth login --email home@example.com"*) true ;; *) false ;; esac \
  && case "$out" in *"the token's owner is unknown"*) true ;; *) false ;; esac \
  && case "$out" in *save*) false ;; *) true ;; esac \
  && ok "a foreign token after the write: exit 4, neither record rewritten, sign-in advice, never save" \
  || bad "a foreign token was clobbered or misreported" "rc=$rc $out"
rm -rf "$T"

# 24 — a session rewrites the token between use's write and its read-back: exit 4, .claude.json untouched
new_env; seed_live home@example.com; seed_slot work@example.com
ccj_before=$(jq -cS . "$CCJ")
export STUB_REFRESH_AFTER_ADD=1
out=$(bash "$SCRIPT" use work --no-chrome 2>&1); rc=$?
unset STUB_REFRESH_AFTER_ADD
[ $rc -eq 4 ] && [ "$(kc_get "$STUB_LIVE" .claudeAiOauth.accessToken)" = "refreshed-in-gap" ] \
  && [ "$(jq -cS . "$CCJ")" = "$ccj_before" ] \
  && case "$out" in *"the token's owner is unknown"*"claude auth login --email home@example.com"*) true ;; *) false ;; esac \
  && ok "a token written into the read-back gap: exit 4, .claude.json untouched, the session's token kept" \
  || bad "the read-back gap refresh" "rc=$rc $out"
rm -rf "$T"

# 25 — only an MCP login changes in the read-back gap: the token landed, so the switch continues
new_env; seed_live home@example.com; seed_slot work@example.com
export STUB_MCP_REFRESH_AFTER_ADD=1
out=$(bash "$SCRIPT" use work --no-chrome 2>&1); rc=$?
unset STUB_MCP_REFRESH_AFTER_ADD
[ $rc -eq 0 ] && [ "$(kc_get "$STUB_LIVE" .claudeAiOauth.accessToken)" = "TOK-work@example.com-slot" ] \
  && [ "$(mcp_test_key)" = "1" ] && [ "$(ccj_email)" = "work@example.com" ] \
  && ok "an MCP-only refresh in the read-back gap: the switch stands, the MCP change survives" \
  || bad "an MCP-only refresh failed the switch or was lost" "rc=$rc $out"
rm -rf "$T"

# 26 — an MCP-only refresh during a failed confirmation: restore only the token, keep the MCP change
new_env; seed_live home@example.com; seed_slot work@example.com
export STUB_STATUS_SCRIPT="$T/status-script"; printf 'ok ok fail fail fail' > "$STUB_STATUS_SCRIPT"
export STUB_MCP_REFRESH_ON_STATUS_FROM=3
bash "$SCRIPT" use work --no-chrome >/dev/null 2>&1; rc=$?
unset STUB_STATUS_SCRIPT STUB_MCP_REFRESH_ON_STATUS_FROM
[ $rc -eq 3 ] && [ "$(kc_get "$STUB_LIVE" .claudeAiOauth.accessToken)" = "TOK-home@example.com" ] \
  && [ "$(mcp_test_key)" = "1" ] && [ "$(ccj_email)" = "home@example.com" ] \
  && ok "a failed switch restores only the token part; an MCP refresh in the window survives (exit 3)" \
  || bad "the rollback clobbered an MCP refresh" "rc=$rc"
rm -rf "$T"

# 27 — the rollback's own token write fails: the identity is not rewritten over the target's token
# Live-item writes: 1 use's own write, 2 the rollback.
new_env; seed_live home@example.com; seed_slot work@example.com
export STUB_STATUS_SCRIPT="$T/status-script"; printf 'ok ok fail fail fail' > "$STUB_STATUS_SCRIPT"
export STUB_FAIL_WRITE_FROM=2
out=$(bash "$SCRIPT" use work --no-chrome 2>&1); rc=$?
unset STUB_STATUS_SCRIPT STUB_FAIL_WRITE_FROM
[ $rc -eq 4 ] && [ "$(kc_get "$STUB_LIVE" .claudeAiOauth.accessToken)" = "TOK-work@example.com-slot" ] \
  && [ "$(ccj_email)" = "work@example.com" ] \
  && case "$out" in *"restoring home@example.com failed"*"claude auth login --email home@example.com"*) true ;; *) false ;; esac \
  && ok "a failed token restore leaves token and identity on one account, exit 4" \
  || bad "the identity was restored over a token that stayed the target's" "rc=$rc $out"
rm -rf "$T"

# 28 — the rollback reads fresh: an MCP change on its classify read (A) or its compare read (B) survives
# Live-item reads on this path: 1 read_live_as, 2 the pre-write re-read, 3 kc_write's read-back,
# 4 the rollback's classify read (A), 5 its compare read just before the write (B).
for case_n in 4 5; do
  new_env; seed_live home@example.com; seed_slot work@example.com
  export STUB_STATUS_SCRIPT="$T/status-script"; printf 'ok ok fail fail fail' > "$STUB_STATUS_SCRIPT"
  export STUB_MCP_REFRESH_ON_READ=$case_n
  bash "$SCRIPT" use work --no-chrome >/dev/null 2>&1; rc=$?
  unset STUB_STATUS_SCRIPT STUB_MCP_REFRESH_ON_READ
  [ $rc -eq 3 ] && [ "$(kc_get "$STUB_LIVE" .claudeAiOauth.accessToken)" = "TOK-home@example.com" ] \
    && [ "$(mcp_test_key)" = "1" ] \
    && ok "the rollback composes from its freshest read (MCP change on live read $case_n survives)" \
    || bad "the rollback wrote stale bytes (MCP change on live read $case_n lost)" "rc=$rc"
  rm -rf "$T"
done

# 28b — save and use serialize: with the lock held by a live pid, use says so and changes nothing
new_env; seed_live home@example.com; seed_slot work@example.com
mkdir -p "$HOME/.local/state/claude-acct"; ln -s "$$" "$HOME/.local/state/claude-acct/lock"
snap=$(snapshot)
out=$(bash "$SCRIPT" use work --no-chrome --expect-from home@example.com 2>&1); rc=$?
[ $rc -eq 2 ] && [ "$(snapshot)" = "$snap" ] && case "$out" in *"holds the lock"*) true ;; *) false ;; esac \
  && ok "use under a held lock: exit 2, says another run holds the lock, nothing changed" \
  || bad "use under a held lock" "rc=$rc $out"
rm -rf "$T"

# Live-item reads on the confirm-failure path: 1 read_live_as, 2 the pre-write re-read, 3 kc_write's
# read-back, 4 the rollback's classify read (A), 5 its compare read (B), 6 the compare after a
# reclassification (B2). Live writes: 1 use's own, 2 the rollback's.
live_writes() { cat "$STUB_KC.live-writes" 2>/dev/null || echo 0; }

# 31 — the bytes move twice before the rollback writes, and the newest read is a foreign token:
#      exit 4, the rollback writes nothing over it
new_env; seed_live home@example.com; seed_slot work@example.com
export STUB_STATUS_SCRIPT="$T/status-script"; printf 'ok ok fail fail fail' > "$STUB_STATUS_SCRIPT"
export STUB_MCP_REFRESH_ON_READ=5 STUB_REFRESH_ON_READ=6
out=$(bash "$SCRIPT" use work --no-chrome 2>&1); rc=$?
unset STUB_STATUS_SCRIPT STUB_MCP_REFRESH_ON_READ STUB_REFRESH_ON_READ
[ $rc -eq 4 ] && [ "$(live_writes)" = "1" ] && [ "$(kc_get "$STUB_LIVE" .claudeAiOauth.accessToken)" = "refreshed-on-read" ] \
  && case "$out" in *"the token's owner is unknown"*) true ;; *) false ;; esac \
  && ok "bytes moving twice to a foreign token: exit 4, no rollback write over it" \
  || bad "the rollback wrote stale bytes over a newly seen foreign token" "rc=$rc writes=$(live_writes) $out"
rm -rf "$T"
# 31b — the bytes move twice (MCP-only both times): never write a composition the newest read did not
#       produce; exit 4 with the restore-failed advice, the target's token and both MCP changes intact
new_env; seed_live home@example.com; seed_slot work@example.com
export STUB_STATUS_SCRIPT="$T/status-script"; printf 'ok ok fail fail fail' > "$STUB_STATUS_SCRIPT"
export STUB_MCP_REFRESH_ON_READ=5,6
out=$(bash "$SCRIPT" use work --no-chrome 2>&1); rc=$?
unset STUB_STATUS_SCRIPT STUB_MCP_REFRESH_ON_READ
[ $rc -eq 4 ] && [ "$(live_writes)" = "1" ] && [ "$(mcp_test_key)" = "2" ] \
  && [ "$(kc_get "$STUB_LIVE" .claudeAiOauth.accessToken)" = "TOK-work@example.com-slot" ] \
  && case "$out" in *"AND restoring home@example.com failed"*"claude auth login --email home@example.com"*) true ;; *) false ;; esac \
  && ok "bytes still moving at the second compare: exit 4, nothing written over them" \
  || bad "the rollback wrote over bytes that kept moving" "rc=$rc writes=$(live_writes) mcp=$(mcp_test_key) $out"
rm -rf "$T"

# 32 — the rollback's write lands, and only an MCP login changes in its read-back gap: the token is
#      the original, so the identity is restored too (exit 3), not left on the target
new_env; seed_live home@example.com; seed_slot work@example.com
export STUB_STATUS_SCRIPT="$T/status-script"; printf 'ok ok fail fail fail' > "$STUB_STATUS_SCRIPT"
export STUB_MCP_REFRESH_AFTER_ADD=2
bash "$SCRIPT" use work --no-chrome >/dev/null 2>&1; rc=$?
unset STUB_STATUS_SCRIPT STUB_MCP_REFRESH_AFTER_ADD
[ $rc -eq 3 ] && [ "$(kc_get "$STUB_LIVE" .claudeAiOauth.accessToken)" = "TOK-home@example.com" ] \
  && [ "$(mcp_test_key)" = "1" ] && [ "$(ccj_email)" = "home@example.com" ] \
  && ok "an MCP refresh in the rollback's read-back gap: token and identity both back (exit 3)" \
  || bad "the rollback read-back gap left token and identity on different accounts" "rc=$rc ccj=$(ccj_email)"
rm -rf "$T"

# 33 — the rollback cannot read the live item (a keychain read failure, not "absent"): write nothing
new_env; seed_live home@example.com; seed_slot work@example.com
export STUB_STATUS_SCRIPT="$T/status-script"; printf 'ok ok fail fail fail' > "$STUB_STATUS_SCRIPT"
export STUB_FAIL_READ_AT=4
out=$(bash "$SCRIPT" use work --no-chrome 2>&1); rc=$?
unset STUB_STATUS_SCRIPT STUB_FAIL_READ_AT
[ $rc -eq 4 ] && [ "$(live_writes)" = "1" ] \
  && [ "$(kc_get "$STUB_LIVE" .claudeAiOauth.accessToken)" = "TOK-work@example.com-slot" ] \
  && [ "$(ccj_email)" = "work@example.com" ] \
  && case "$out" in *"AND restoring home@example.com failed"*) true ;; *) false ;; esac \
  && ok "an unreadable live item during rollback: exit 4, nothing overwritten, token and identity agree" \
  || bad "an unreadable live item was overwritten during rollback" "rc=$rc writes=$(live_writes) $out"
rm -rf "$T"
# 33b — the forward write did not land and the classify read fails: exit 4, no second live write
new_env; seed_live home@example.com; seed_slot work@example.com
export STUB_FAIL_WRITE="$STUB_LIVE" STUB_FAIL_READ_AT=4
out=$(bash "$SCRIPT" use work --no-chrome 2>&1); rc=$?
unset STUB_FAIL_WRITE STUB_FAIL_READ_AT
adds=$(cat "$STUB_KC.live-write-attempts" 2>/dev/null || echo 0)
[ $rc -eq 4 ] && [ "$adds" = "1" ] && [ "$(ccj_email)" = "home@example.com" ] \
  && case "$out" in *"could not be read back"*"claude auth login --email home@example.com"*) true ;; *) false ;; esac \
  && ok "an unreadable live item after a failed write: exit 4, no overwrite attempted" \
  || bad "an unreadable live item after a failed write was overwritten" "rc=$rc adds=$adds $out"
rm -rf "$T"

# 34 — list --json refuses a short array: a row that cannot be rendered fails the whole list (exit 2)
new_env; seed_live alpha@x.test
acct_file 'a\talpha@x.test\nb\tbeta@x.test\nc\tgamma@x.test\n'
REAL_JQ=$(PATH=/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin command -v jq)
printf '#!/bin/bash\ncase " $* " in *" beta@x.test "*) exit 3 ;; esac\nexec "%s" "$@"\n' "$REAL_JQ" > "$T/bin/jq"; chmod +x "$T/bin/jq"
out=$(bash "$SCRIPT" list --json 2>/dev/null); rc=$?
[ $rc -eq 2 ] && [ -z "$out" ] && ok "list --json with an unrenderable row: exit 2, prints no partial array" \
  || bad "list --json printed a short array as the whole fleet" "rc=$rc out=$out"
rm -f "$T/bin/jq"
out=$(bash "$SCRIPT" list --json 2>/dev/null); rc=$?
[ $rc -eq 0 ] && printf '%s' "$out" | jq -e 'length==3' >/dev/null \
  && ok "list --json without the failing shim lists all three" || bad "list --json baseline" "rc=$rc $out"
rm -rf "$T"
# 34b — a refresh expiry jq prints in scientific notation (a corrupt slot) is not bash arithmetic:
#       the row says the slot is unusable, and the rows after it are still listed
new_env; seed_live alpha@x.test; seed_slot alpha@x.test; seed_slot beta@x.test "" 1e28; seed_slot gamma@x.test
acct_file 'a\talpha@x.test\nb\tbeta@x.test\nc\tgamma@x.test\n'
out=$(bash "$SCRIPT" list --json 2>/dev/null); rc=$?
[ $rc -eq 0 ] && printf '%s' "$out" | jq -e 'length==3 and (.[1].email=="beta@x.test") and .[1].slot_ok==false
    and (.[1].slot_problem|test("refresh-token expiry")) and .[1].refresh_until==null and .[2].email=="gamma@x.test"' >/dev/null \
  && ok "list --json: an unreadable refresh expiry flags that slot and lists every account" \
  || bad "list --json with an unreadable refresh expiry" "rc=$rc $out"
out=$(bash "$SCRIPT" list 2>&1); rc=$?
[ $rc -eq 0 ] && case "$out" in *"beta@x.test"*"unreadable refresh-token expiry"*"gamma@x.test"*) true ;; *) false ;; esac \
  && ok "plain list: the unreadable expiry is named and the next account still prints" \
  || bad "plain list with an unreadable refresh expiry" "rc=$rc $out"
rm -rf "$T"
# 34c — the loop's subshell dying mid-list prints no completeness record, so no short array passes:
#       a `date` shim kills its parent (that subshell) on the second account's expiry lookup
new_env; seed_live alpha@x.test; seed_slot alpha@x.test; seed_slot beta@x.test; seed_slot gamma@x.test
acct_file 'a\talpha@x.test\nb\tbeta@x.test\nc\tgamma@x.test\n'
printf '#!/bin/bash\nif [ "${1:-}" = -r ]; then n=$(( $(cat "%s/date-r" 2>/dev/null || echo 0) + 1 )); echo "$n" > "%s/date-r"\n  [ "$n" -eq 2 ] && kill -9 "$PPID"; fi\nexec /bin/date "$@"\n' "$T" "$T" > "$T/bin/date"; chmod +x "$T/bin/date"
out=$(bash "$SCRIPT" list --json 2>/dev/null); rc=$?
[ "$(cat "$T/date-r" 2>/dev/null)" -ge 2 ] 2>/dev/null && [ $rc -eq 2 ] && [ -z "$out" ] \
  && ok "list --json: a loop killed mid-list exits 2 and prints no partial array" \
  || bad "list --json accepted a list cut short by a killed loop" "rc=$rc date-r=$(cat "$T/date-r" 2>/dev/null) out=$out"
rm -rf "$T"

# 34d — list --json refuses when a source of the account list cannot be read: a corrupt
#       switches log or an unreadable accounts file would otherwise drop accounts and still
#       print a "complete" shorter array
new_env; seed_live alpha@x.test; seed_slot alpha@x.test; seed_slot beta@x.test
acct_file 'a\talpha@x.test\nb\tbeta@x.test\n'
mkdir -p "$HOME/.local/state/claude-acct"; printf '{"from":"alpha@x.test","to":"gamma@x.test"}\n{not json\n' > "$HOME/.local/state/claude-acct/switches.jsonl"
out=$(bash "$SCRIPT" list --json 2>/dev/null); rc=$?
[ $rc -eq 2 ] && [ -z "$out" ] && ok "list --json with a corrupt switches log: exit 2, prints no array" \
  || bad "list --json read past a corrupt switches log" "rc=$rc out=$out"
rm -f "$HOME/.local/state/claude-acct/switches.jsonl"
out=$(bash "$SCRIPT" list --json 2>/dev/null); rc=$?
[ $rc -eq 0 ] && printf '%s' "$out" | jq -e 'length==2' >/dev/null && ok "list --json without the corrupt log lists both" \
  || bad "list --json baseline after removing the corrupt log" "rc=$rc $out"
chmod 000 "$HOME/.config/claude-acct/accounts"
out=$(bash "$SCRIPT" list --json 2>/dev/null); rc=$?
chmod 600 "$HOME/.config/claude-acct/accounts"
[ $rc -eq 2 ] && [ -z "$out" ] && ok "list --json with an unreadable accounts file: exit 2, prints no array" \
  || bad "list --json read past an unreadable accounts file" "rc=$rc out=$out"
rm -rf "$T"

# 35 — chrome reports a failed open (exit 3); use still succeeds when only Chrome failed
new_env; seed_live home@example.com; seed_slot work@example.com
printf '#!/bin/bash\nexit 1\n' > "$T/bin/open"; chmod +x "$T/bin/open"
out=$(bash "$SCRIPT" chrome work 2>&1); rc=$?
[ $rc -eq 3 ] && case "$out" in *"could not open"*) true ;; *) false ;; esac \
  && ok "chrome with a failing open: exit 3, says so" || bad "chrome reported success after a failed open" "rc=$rc $out"
bash "$SCRIPT" use work >/dev/null 2>&1; rc=$?
[ $rc -eq 0 ] && [ "$(ccj_email)" = "work@example.com" ] \
  && ok "a failed Chrome open never fails a switch that landed" || bad "use failed on a Chrome open error" "rc=$rc"
rm -rf "$T"

# 29 — where names the credential store and reads no credential
new_env
out=$(bash "$SCRIPT" where 2>&1); rc=$?
[ $rc -eq 0 ] && [ "$out" = "$(printf 'config_dir=%s\nkeychain_account=tester\nstate_dir=%s' "$CLAUDE_CONFIG_DIR" "$HOME/.local/state/claude-acct")" ] \
  && [ ! -s "$STUB_ARGV_LOG" ] \
  && ok "where prints config_dir, keychain_account, and state_dir, and calls security never" || bad "where" "rc=$rc $out"
bash "$SCRIPT" where extra >/dev/null 2>&1; [ $? -eq 1 ] && ok "where refuses arguments" || bad "where took an argument"
out=$(CLAUDE_ACCT_STATE_DIR=/x bash "$SCRIPT" where 2>&1); rc=$?
[ $rc -eq 0 ] && [ "$(printf '%s\n' "$out" | sed -n 3p)" = "state_dir=/x" ] && [ ! -s "$STUB_ARGV_LOG" ] \
  && ok "where honors CLAUDE_ACCT_STATE_DIR (state_dir=/x), and calls security never" || bad "where state_dir override" "rc=$rc $out"
rm -rf "$T"

# 30 — chrome opens the account's profile; no profile is exit 2; no argument is exit 1
new_env
out=$(bash "$SCRIPT" chrome work 2>&1); rc=$?
[ $rc -eq 0 ] && [ "$(tr '\n' '|' < "$STUB_OPEN_LOG" 2>/dev/null)" = "-na|Google Chrome|--args|--profile-directory=Profile 1|" ] \
  && ok "chrome work opens Profile 1" || bad "chrome did not open the profile" "rc=$rc $out"
acct_file 'np\tnoprof@x.test\n'; : > "$STUB_OPEN_LOG"
bash "$SCRIPT" chrome np >/dev/null 2>&1; rc=$?
[ $rc -eq 2 ] && [ ! -s "$STUB_OPEN_LOG" ] && ok "chrome with no profile set: exit 2, opens nothing" || bad "chrome with no profile" "rc=$rc"
bash "$SCRIPT" chrome >/dev/null 2>&1; [ $? -eq 1 ] && ok "chrome with no argument: exit 1" || bad "chrome with no argument"
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

# 36 — record-limits: a statusline payload becomes the newest reading for the account it was made on
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
out=$(bash "$SCRIPT" limits 2>&1)
printf '%s\n' "$out" | grep -Eq '^\* home@example\.com +59%  ' && case "$out" in *"5h: home@example.com 7%"*) true ;; *) false ;; esac \
  && ok "limits reads what record-limits kept (59% left, 5h 7%)" || bad "limits did not show the recorded reading" "$out"
pay 43 "$r1" | bash "$SCRIPT" record-limits
[ "$(jq -r .seven_day_pct "$L/home@example.com.json")" = 43 ] && [ "$(jq -r .five_hour_pct "$L/home@example.com.json")" = null ] \
  && case "$(bash "$SCRIPT" limits 2>&1)" in *"5h:"*) false ;; *) true ;; esac \
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

# 37 — record-limits keeps the higher percent within one reset window, and a token-launched
#      session's reading is filed only by its reset time. Every call runs under a stand-in `claude`
#      parent: record-limits looks for CLAUDE_CODE_OAUTH_TOKEN in the environment of each process
#      from its parent up to the first `claude`, because Claude Code removes that variable from the
#      statusline command's own environment. The stand-in is a symlink to node, not bash: macOS
#      hides a system binary's environment (/bin/bash, /bin/sh) from `ps -E`, while the claude
#      binary's is readable. Without node these cases cannot run, and they say so.
NODE_BIN=$(PATH=/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin command -v node 2>/dev/null)
if [ -z "$NODE_BIN" ]; then
  printf '  SKIP 37: node not found, so the token-session stand-in cannot run (not a pass)\n'
else
new_env; seed_live home@example.com
export CLAUDE_ACCT_LIMITS_DIR="$T/limits"; L="$T/limits/latest"; mkdir -p "$L"
mkdir -p "$T/fake"; ln -sf "$NODE_BIN" "$T/fake/claude"
FAKE_JS='const e = {...process.env}; delete e.CLAUDE_CODE_OAUTH_TOKEN;
const r = require("child_process").spawnSync("bash", process.argv.slice(1), {stdio: "inherit", env: e});
process.exit(r.status === null ? 1 : r.status);'
rl() { env -u CLAUDE_CODE_OAUTH_TOKEN "$T/fake/claude" -e "$FAKE_JS" "$SCRIPT" record-limits; }
rl_token() { env CLAUDE_CODE_OAUTH_TOKEN=test-not-a-token "$T/fake/claude" -e "$FAKE_JS" "$SCRIPT" record-limits; }
pay2() {  # $1 7-day pct  $2 7-day reset  [$3 5-hour pct  $4 5-hour reset]
  local fh=""; [ -n "${3:-}" ] && fh=",\"five_hour\":{\"used_percentage\":$3,\"resets_at\":$4}"
  printf '{"version":"2.1.319","rate_limits":{"seven_day":{"used_percentage":%s,"resets_at":%s}%s}}' "$1" "$2" "$fh"
}
now=$(date +%s); w1=$((now + 86400)); w2=$((now + 3 * 86400)); f1=$((now + 3600)); f2=$((now + 7200))
pay2 60 "$w1" 30 "$f1" | rl; pay2 40 "$w1" 20 "$f1" | rl
[ "$(jq -c '[.seven_day_pct,.five_hour_pct]' "$L/home@example.com.json")" = "[60,30]" ] \
  && ok "60 then 40 in one 7-day window keeps 60; 30 then 20 in one 5-hour window keeps 30" \
  || bad "a lower reading in the same window replaced a higher one" "$(cat "$L/home@example.com.json")"
pay2 65 "$w1" 35 "$f1" | rl
[ "$(jq -c '[.seven_day_pct,.five_hour_pct]' "$L/home@example.com.json")" = "[65,35]" ] \
  && ok "a higher reading in the window still replaces the stored one" || bad "a higher reading was dropped" "$(cat "$L/home@example.com.json")"
pay2 50 "$w1" 2 "$f2" | rl
[ "$(jq -c '[.seven_day_pct,.five_hour_pct,.five_hour_resets_at]' "$L/home@example.com.json")" = "[65,2,$f2]" ] \
  && ok "a new 5-hour window takes its lower figure while the 7-day max holds" || bad "5-hour window change" "$(cat "$L/home@example.com.json")"
pay2 3 "$w2" | rl
[ "$(jq -c '[.seven_day_pct,.seven_day_resets_at]' "$L/home@example.com.json")" = "[3,$w2]" ] \
  && ok "a new 7-day window takes its own lower figure" || bad "7-day window change" "$(cat "$L/home@example.com.json")"
# Token sessions. home@ now sits in window w2; work@ has its own window w3.
w3=$((now + 5 * 86400))
printf '{"captured_at":"2026-11-05T00:00:00Z","email":"work@example.com","seven_day_pct":10,"seven_day_resets_at":%s}\n' "$w3" > "$L/work@example.com.json"
before=$(cat "$L"/*.json)
out=$(pay2 88 $((now + 9 * 86400)) | rl_token 2>&1); rc=$?
[ $rc -eq 0 ] && [ -z "$out" ] && [ "$(cat "$L"/*.json)" = "$before" ] \
  && ok "a token session whose reset matches no account writes nothing, silently" \
  || bad "an unmatched token-session reading was filed" "rc=$rc out=$out $(cat "$L"/*.json)"
pay2 4 "$w2" | rl_token
[ "$(jq -r .seven_day_pct "$L/home@example.com.json")" = 4 ] \
  && ok "a token session in the live account's window is the live account's" || bad "token reading in the live window" "$(cat "$L/home@example.com.json")"
pay2 12 "$w3" | rl_token
[ "$(jq -r .seven_day_pct "$L/work@example.com.json")" = 12 ] && [ "$(jq -r .seven_day_pct "$L/home@example.com.json")" = 4 ] \
  && ok "a token session in another account's window is that account's" || bad "token reading in another window" "$(cat "$L"/*.json)"
pay2 9 $((now + 9 * 86400)) | rl
[ "$(jq -r .seven_day_pct "$L/home@example.com.json")" = 9 ] \
  && ok "without a token the same unmatched reading still goes to the live account" || bad "non-token unmatched reading" "$(cat "$L/home@example.com.json")"
# The per-account lock: a fresh one held by another writer skips this write and stays; a stale one
# (older than a minute) is cleared, the write lands, and the lock is released.
w9=$((now + 9 * 86400))
mkdir "$L/.home@example.com.lock"
pay2 20 "$w9" | rl
[ "$(jq -r .seven_day_pct "$L/home@example.com.json")" = 9 ] && [ -d "$L/.home@example.com.lock" ] \
  && ok "a held lock skips the write and is left to its holder" || bad "held lock" "$(cat "$L/home@example.com.json")"
touch -t 202001010000 "$L/.home@example.com.lock"
pay2 21 "$w9" | rl
[ "$(jq -r .seven_day_pct "$L/home@example.com.json")" = 9 ] && [ ! -d "$L/.home@example.com.lock" ] \
  && ok "a stale lock is cleared and that reading skipped, so two clearers never both write" \
  || bad "stale lock clear" "$(cat "$L/home@example.com.json")"
pay2 22 "$w9" | rl
[ "$(jq -r .seven_day_pct "$L/home@example.com.json")" = 22 ] && [ ! -d "$L/.home@example.com.lock" ] \
  && ok "the next reading takes the freed lock, writes, and releases it" || bad "write after a stale clear" "$(cat "$L/home@example.com.json")"
unset CLAUDE_ACCT_LIMITS_DIR
rm -rf "$T"
fi
rm -rf "$T"

printf '\n  %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
