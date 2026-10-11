#!/usr/bin/env bash
# Push every entry in .dev.vars to the Worker as an encrypted Cloudflare secret.
#
# Values are piped on stdin to `wrangler secret put`, so they never appear in
# shell history, in `ps` output, or in any log.
set -euo pipefail
cd "$(dirname "$0")"

if [[ ! -f .dev.vars ]]; then
    echo "missing .dev.vars — copy .dev.vars.example and fill it in first" >&2
    exit 1
fi

fail=0
while IFS= read -r line || [[ -n "$line" ]]; do
    # skip blanks and comments
    case "$line" in ''|'#'*) continue ;; esac
    [[ "$line" == *=* ]] || continue

    key="${line%%=*}"
    val="${line#*=}"
    # strip optional surrounding quotes
    val="${val%\"}"; val="${val#\"}"


    # Names already declared as plain [vars] in wrangler.toml cannot also be
    # secrets — Cloudflare rejects the duplicate.
    case "$key" in
        ILETCOMFORT_REGION|POLL_DEVICES)
            printf '  %-28s SKIPPED (plain var in wrangler.toml)\n' "$key"
            continue ;;
    esac
    if [[ -z "$val" ]]; then
        printf '  %-28s SKIPPED (empty)\n' "$key"
        continue
    fi

    printf '  %-28s ' "$key"
    if printf '%s' "$val" | wrangler secret put "$key" >/dev/null 2>&1; then
        echo "ok"
    else
        echo "FAILED"
        fail=1
    fi
done < .dev.vars

echo
if (( fail )); then
    echo "one or more secrets failed — check \`wrangler whoami\`" >&2
    exit 1
fi
echo "all secrets set. next: wrangler deploy"
