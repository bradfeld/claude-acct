# claude-acct

Switch the Claude subscription every Claude Code session on a Mac uses, in place, with one command - and bring up the matching Chrome profile so Claude in Chrome is on the same account.

```
$ claude-acct.sh use work
switched you@personal.example -> you@company.example
```

It is one bash script (macOS, bash 3.2, `jq`, `/usr/bin/security`, and `python3` for the reports) and a hermetic test suite. The full design write-up, including how it compares to [claude-rotator](https://github.com/mpavlyukovskyy/claude-rotator), is in [`docs/claude-account-switcher.html`](docs/claude-account-switcher.html) - download it and open it in a browser.

## How it works

Claude Code keeps an account in two places: an OAuth token under the `claudeAiOauth` key of a Keychain item (`Claude Code-credentials`, with a `-<sha256(config dir)[0:8]>` suffix when `CLAUDE_CONFIG_DIR` is set), and an identity record, `oauthAccount`, in `.claude.json`. The token carries no email or org, so swapping it alone leaves Claude Code naming the old account. `claude-acct.sh` parks each account's `{claudeAiOauth, oauthAccount}` pair in its own Keychain item (`claude-acct/<email>`), and `use` swaps both into place - the token by changing only that one key (every MCP server's OAuth login lives in the same item and stays put), the identity under Claude Code's own `.claude.json.lock` - then confirms with `claude auth status` and rolls both back on any failure.

## Install

```
git clone https://github.com/bradfeld/claude-acct.git
cp claude-acct/claude-acct.sh ~/bin/          # anywhere on PATH
bash claude-acct/claude-acct.test.sh          # hermetic: stubs security/claude/open, never touches your Keychain
```

Optional aliases and Chrome profiles, tab-separated, in `~/.config/claude-acct/accounts`:

```
home	you@personal.example	Profile 3
work	you@company.example	Profile 4
```

The profile directory is the last segment of "Profile Path" on `chrome://version`. Sign each Chrome profile in to claude.ai and the Claude extension once; a switch only brings the right profile forward.

## Use

```
claude-acct.sh add you@company.example   # once per account: browser sign-in in that account's Chrome profile
claude-acct.sh list                      # saved accounts, which is live, refresh-token expiry (~4 weeks)
claude-acct.sh use work                  # switch
claude-acct.sh whoami
claude-acct.sh limits                    # 7-day (and 5-hour, where the plan has one) quota per account
claude-acct.sh usage --days 7            # transcript tokens per account, attributed by switch time
```

Exit codes: `0` ok, `1` usage error, `2` refused with nothing changed, `3` switch failed and both records were restored, `4` the restore failed too (the message names the recovery command).

### Quota per account

Claude Code hands a statusline command the live session's `rate_limits`, but not which account they belong to. To have `limits` show every account's headroom, pipe that payload through `record-limits` from your statusline script:

```bash
#!/bin/bash
input=$(cat)
printf '%s' "$input" | claude-acct.sh record-limits    # prints nothing, always exits 0
# ... the rest of your statusline, reading "$input"
```

A reading is filed under the account whose 7-day reset time it carries when that matches exactly one other known account (a session that had not followed a switch yet), and under the live account otherwise. Accounts you have not used since recording began say "no reading", never 0%.

## What follows a switch

- New sessions: immediately.
- Running sessions: at their next request. Before each request Claude Code re-reads the Keychain login and adopts a changed one. Measured on 2.1.317 with no restart: running sessions' quota readings moved to the new account within about two minutes. An idle session moves when next used; for one that did not, `/exit` then `claude --continue` moves it with its conversation intact.
- Anything started with `CLAUDE_CODE_OAUTH_TOKEN`, and sandboxed launchd jobs that cannot reach the Keychain: never.
- If `<config dir>/.credentials.json` exists (Claude Code's plaintext fallback when a Keychain write fails), running sessions watch that file instead of the Keychain and stop following. Move it aside; `use` warns when it is present.

## Residual risk

- **Write-back.** Nothing makes the Keychain write and the `.claude.json` write one atomic step, and Claude Code takes no lock on the Keychain item. A session still on the old account can write it back with a token refresh or its own config write. The post-switch check proves the switch landed, not that nothing undoes it later.
- **Refresh-token rotation.** Reported by Mark Pavlyukovskyy: a refresh can revoke the previous refresh token, so if a session still on account A refreshes after `use` parked A, A's slot holds a dead token and the next `use` back to A fails its sign-in. `use` re-parks the outgoing account from the live item at every switch, which bounds how stale a slot gets; one `add` repairs a dead one.

## Terms

This rotates subscriptions you own, for your own use. Every model request still goes through the unmodified `claude` binary; no token is handed to another process, leased, or sent anywhere.

## License

MIT. See [LICENSE](LICENSE).
