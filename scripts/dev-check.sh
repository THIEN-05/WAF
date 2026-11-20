#!/usr/bin/env sh
set -u

missing=0

check_command() {
  command_name=$1
  display_name=$2
  if command -v "$command_name" >/dev/null 2>&1; then
    printf 'OK      %s: %s\n' "$display_name" "$(command -v "$command_name")"
  else
    printf 'MISSING %s\n' "$display_name"
    missing=1
  fi
}

check_command go Go
check_command docker Docker
check_command make make
check_command gcc gcc
check_command golangci-lint golangci-lint

if command -v docker >/dev/null 2>&1; then
  if docker compose version >/dev/null 2>&1; then
    printf 'OK      Docker Compose\n'
  else
    printf 'MISSING Docker Compose plugin\n'
    missing=1
  fi
fi

exit "$missing"
