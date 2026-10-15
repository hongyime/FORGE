#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
config=${FORGE_AUTOSTART_CONFIG:-$repo_root/imports/autostart.local.json}
timeout_seconds=${FORGE_AUTOSTART_TIMEOUT_SECONDS:-9000}
every_seconds=${FORGE_AUTOSTART_EVERY_SECONDS:-9300}
startup_delay=${FORGE_AUTOSTART_STARTUP_DELAY_SECONDS:-300}
failure_backoff=${FORGE_AUTOSTART_FAILURE_BACKOFF_SECONDS:-1800}
max_failures=${FORGE_AUTOSTART_MAX_CONSECUTIVE_FAILURES:-3}
unit_dir=${XDG_CONFIG_HOME:-${HOME:?HOME is required}/.config}/systemd/user
unit_file=$unit_dir/forge-guarded-autostart.service
timer_file=$unit_dir/forge-guarded-autostart.timer
log_dir=${XDG_STATE_HOME:-${HOME:?HOME is required}/.local/state}/forge

run_cycle() {
    mkdir -p "$log_dir"
    if [ "${loop_lock_held:-0}" != 1 ]; then
        exec 9>"$log_dir/guarded-autostart.lock"
        flock -n 9 || { echo "guarded autostart already running"; return 0; }
    fi
    cd "$repo_root"
    if [ -x "$repo_root/.venv/bin/python" ]; then
        python=$repo_root/.venv/bin/python
    else
        python=python3
    fi
    timeout --preserve-status "$timeout_seconds" "$python" -m forge.cli automation cycle \
        --autostart-config "$config" --apply --live --json --docker-probe-mode compose-dependency
}

run_loop() {
    sleep "$startup_delay"
    failures=0
    while :; do
        if run_cycle; then
            failures=0
            sleep "$every_seconds"
        else
            rc=$?
            failures=$((failures + 1))
            if [ "$failures" -ge "$max_failures" ]; then
                echo "guarded autostart exiting after $failures consecutive failures" >&2
                return "$rc"
            fi
            sleep "$failure_backoff"
        fi
    done
}

case ${1:-install} in
    --run-once)
        run_cycle
        ;;
    --run-loop)
        mkdir -p "$log_dir"
        exec 9>"$log_dir/guarded-autostart.lock"
        flock -n 9 || { echo "guarded autostart already running"; exit 0; }
        loop_lock_held=1
        run_loop
        ;;
    --uninstall)
        systemctl --user disable --now forge-guarded-autostart.service 2>/dev/null || true
        rm -f "$unit_file"
        rm -f "$timer_file"
        systemctl --user daemon-reload
        echo "Removed forge guarded autostart user timer"
        ;;
    install)
        command -v systemctl >/dev/null 2>&1 || { echo "systemctl is required" >&2; exit 1; }
        command -v flock >/dev/null 2>&1 || { echo "flock is required" >&2; exit 1; }
        command -v timeout >/dev/null 2>&1 || { echo "timeout is required" >&2; exit 1; }
        mkdir -p "$unit_dir"
        cat >"$unit_file" <<EOF
[Unit]
Description=FORGE guarded autostart apply cycle

[Service]
Type=simple
WorkingDirectory=$repo_root
ExecStart=$script_dir/install_guarded_autostart_task.sh --run-loop
Restart=no

[Install]
WantedBy=default.target
EOF
        systemctl --user daemon-reload
        systemctl --user enable --now forge-guarded-autostart.service
        echo "Installed guarded autostart user service (config: $config; timeout: ${timeout_seconds}s; interval: ${every_seconds}s)"
        ;;
    *)
        echo "Usage: $0 [install|--run-once|--run-loop|--uninstall]" >&2
        exit 2
        ;;
esac
