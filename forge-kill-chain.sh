#!/usr/bin/env sh
# FORGE Toolkit - Kill-Chain POSIX launcher.

ROOT=$(CDPATH= cd "$(dirname "$0")" && pwd -P) || exit 1
cd "$ROOT" || exit 1
VENV_PYTHON="$ROOT/.venv/bin/python"
VENV_FORGE="$ROOT/.venv/bin/forge"

wait_if_interactive() {
    if [ -t 0 ]; then
        printf '%s' "$1"
        IFS= read -r _forge_wait || :
    fi
}

is_yes() {
    case "$1" in
        [Yy] | [Yy][Ee][Ss]) return 0 ;;
        *) return 1 ;;
    esac
}

export FORGE_NO_TOR=1

if [ ! -x "$VENV_PYTHON" ] || [ ! -x "$VENV_FORGE" ]; then
    printf '[ERROR] Run ./setup.sh once first.\n'
    wait_if_interactive 'Press Enter to continue...'
    exit 1
fi

printf '\n'
printf '============================================================================\n'
printf '  FORGE Toolkit - Kill-Chain\n'
printf '============================================================================\n\n'
printf ' Seed types accepted:\n'
printf '   - Domain          target.example\n'
printf '   - IPv4            10.0.0.5\n'
printf '   - Email           user@company.com\n'
printf '   - Phone (E.164)   +15551234567\n'
printf '   - Username        @operator\n'
printf '   - Full name       "FORGE Operator"     (quotes required)\n\n'

printf 'Engagement ID (leave BLANK for auto-derive): '
IFS= read -r ENGAGEMENT || ENGAGEMENT=

printf 'Seed identifier: '
IFS= read -r SEED || SEED=
if [ -z "$SEED" ]; then
    printf 'No seed given. Aborting.\n'
    wait_if_interactive 'Press Enter to continue...'
    exit 1
fi

printf '\nOptional flags:\n'
printf '  ACTIVE mode? port scan + cred validation, needs ROE [y/N]: '
IFS= read -r ATTACK || ATTACK=
printf '  Route through Tor? [y/N]: '
IFS= read -r TOR || TOR=
printf '  DRY RUN? log-only, no outbound calls [y/N]: '
IFS= read -r DRYRUN || DRYRUN=
printf '  ROE reference (required for live ACTIVE mode, blank uses FORGE_ROE_ID): '
IFS= read -r ROE || ROE=
printf '  Scope manifest path (required for live ACTIVE mode, blank uses FORGE_SCOPE_MANIFEST): '
IFS= read -r SCOPEMANIFEST || SCOPEMANIFEST=
printf '  Skip cloud discovery? [y/N]: '
IFS= read -r SKIPCLOUD || SKIPCLOUD=
printf '  Skip GitHub keyscan? [y/N]: '
IFS= read -r SKIPKEYSCAN || SKIPKEYSCAN=
printf '  Spider max iterations [7]: '
IFS= read -r MAXITER || MAXITER=
if [ -z "$MAXITER" ]; then
    MAXITER=7
fi

if is_yes "$ATTACK" && ! is_yes "$DRYRUN" && [ -z "$ROE" ] && [ -z "${FORGE_ROE_ID:-}" ]; then
    printf 'Live ACTIVE mode requires a ROE reference. Re-run with a ROE value or set FORGE_ROE_ID.\n'
    wait_if_interactive 'Press Enter to continue...'
    exit 1
fi
if is_yes "$ATTACK" && ! is_yes "$DRYRUN" && [ -z "$SCOPEMANIFEST" ] && [ -z "${FORGE_SCOPE_MANIFEST:-}" ]; then
    printf 'Live ACTIVE mode requires a scope manifest. Re-run with a manifest path or set FORGE_SCOPE_MANIFEST.\n'
    wait_if_interactive 'Press Enter to continue...'
    exit 1
fi

set -- --max-iter "$MAXITER"
if [ -n "$ENGAGEMENT" ]; then
    set -- --engagement "$ENGAGEMENT" "$@"
fi
if is_yes "$ATTACK"; then
    set -- "$@" --attack-mode
fi
if [ -n "$ROE" ]; then
    set -- "$@" --roe-id "$ROE"
fi
if [ -n "$SCOPEMANIFEST" ]; then
    set -- "$@" --scope-manifest "$SCOPEMANIFEST"
fi
if is_yes "$DRYRUN"; then
    set -- "$@" --dry-run
fi
if is_yes "$SKIPCLOUD"; then
    set -- "$@" --skip-cloud
fi
if is_yes "$SKIPKEYSCAN"; then
    set -- "$@" --skip-keyscan
fi
if is_yes "$TOR"; then
    set -- kill-chain "$SEED" "$@"
else
    set -- --no-tor kill-chain "$SEED" "$@"
fi

printf '\nRunning: %s\n' "$VENV_FORGE"
printf 'Arguments:\n'
for arg in "$@"; do
    printf '  %s\n' "$arg"
done
printf '\n'

"$VENV_FORGE" "$@"
EXIT_CODE=$?

printf '\n'
printf '============================================================================\n'
if [ "$EXIT_CODE" -eq 0 ]; then
    printf '  Kill-chain complete.\n'
else
    printf '  Kill-chain exited with code %s.\n' "$EXIT_CODE"
fi
printf '  Report:   reports/engagement_%s_kill_chain_*.md\n' "$ENGAGEMENT"
printf '  Evidence: .forge_data/engagements/%s.db\n' "$ENGAGEMENT"
printf '============================================================================\n'
wait_if_interactive 'Press Enter to continue...'
exit "$EXIT_CODE"
