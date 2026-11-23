#!/bin/bash
set -euo pipefail
export LC_ALL=C
fail() {
    printf 'server_dependency_error manager=%s stage=%s reason=%s code=%s\n' "$manager" "$1" "$2" "${3:-1}" >&2
    exit 1
}
manager=none
[ "$EUID" -eq 0 ] || fail preflight root_required
for tool in bash timeout install cp mktemp chmod mv rm cat dirname readlink ln mkdir rmdir sha256sum; do
    command -v "$tool" >/dev/null || fail preflight "missing_bootstrap_$tool"
done
command -v systemctl >/dev/null || fail preflight systemd_required
[ "$(cat /proc/1/comm)" = systemd ] || fail preflight systemd_required
missing=()
for tool in python3 ip iptables conntrack sysctl ethtool awk; do
    command -v "$tool" >/dev/null || missing+=("$tool")
done
if [ "${#missing[@]}" -eq 0 ]; then
    printf '%s\n' 'server_dependencies_ready installed=0'
    exit 0
fi
for candidate in apt-get dnf yum; do
    if command -v "$candidate" >/dev/null; then manager=$candidate; break; fi
done
[ "$manager" != none ] || fail preflight unsupported_package_manager
packages=()
for tool in "${missing[@]}"; do
    case "$tool" in
        ip) if [ "$manager" = apt-get ]; then package=iproute2; else package=iproute; fi ;;
        conntrack) if [ "$manager" = apt-get ]; then package=conntrack; else package=conntrack-tools; fi ;;
        sysctl) if [ "$manager" = apt-get ]; then package=procps; else package=procps-ng; fi ;;
        awk) package=gawk ;;
        *) package=$tool ;;
    esac
    packages+=("$package")
done
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
execute() {
    local stage=$1 limit=$2 code=0
    shift 2
    timeout --signal=TERM --kill-after=10s "$limit" "$@" >/dev/null 2>&1 || code=$?
    [ "$code" -eq 0 ] || fail "$stage" package_command_failed "$code"
}
printf 'server_dependencies_install manager=%s packages=%s\n' "$manager" "${packages[*]}"
if [ "$manager" = apt-get ]; then
    execute refresh 120s apt-get -o DPkg::Lock::Timeout=30 -o Acquire::Retries=0 -o APT::Update::Error-Mode=any update
    execute install 180s apt-get -o DPkg::Lock::Timeout=30 --yes --no-install-recommends --no-remove --no-upgrade install "${packages[@]}"
else
    execute install 180s "$manager" --setopt=install_weak_deps=False --assumeyes install "${packages[@]}"
fi
for tool in "${missing[@]}"; do
    command -v "$tool" >/dev/null || fail verify "missing_dependency_$tool"
done
printf 'server_dependencies_ready installed=%s\n' "${#packages[@]}"
