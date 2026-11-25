#!/usr/bin/env bash
set -euo pipefail

matches=$(grep -REn --include='*.go' --exclude='*_test.go' \
  'fmt\.Sprintf\([^\n]*(SELECT|INSERT|UPDATE|DELETE|EXECUTE)|["`][^\n]*(SELECT|INSERT|UPDATE|DELETE|EXECUTE)[^\n]*["`][[:space:]]*\+' \
  controlplane/internal || true)
if [[ -n "$matches" ]]; then
  printf '%s\n' "$matches" >&2
  echo 'controlplane SQL must be static and parameterized; dynamic SQL is forbidden' >&2
  exit 1
fi
echo 'controlplane SQL concatenation check passed'
