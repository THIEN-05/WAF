#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
	printf '%s\n' "usage: $0 /path/to/corpus-directory" >&2
	exit 2
fi

corpus_dir=$(cd "$1" && pwd)
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"
WAF_CORPUS_DIR="$corpus_dir" go test -count=1 -v ./edge/internal/waf -run '^TestWAFCorpusMetrics$'
