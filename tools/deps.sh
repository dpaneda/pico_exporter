#!/usr/bin/env bash
# tools/deps.sh - self-bootstrap the build dependencies into build/deps/
# (inside the repo, gitignored). Nothing outside the repository is touched.
#
#   tools/deps.sh bearssl-host    BearSSL lib for the x86_64 -flto link (host cc)
#   tools/deps.sh bearssl-aarch64 BearSSL lib for the aarch64 -flto link
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/tools/bearssl_env.sh"

case "${1:-}" in
  bearssl-host)   build_bearssl_lib_lto "$BEARSSL_LIB_HOST" "${CC:-cc}" ar ;;
  bearssl-aarch64) build_bearssl_lib_lto "$BEARSSL_LIB_AARCH64" ;;
  *) echo "usage: tools/deps.sh <bearssl-host|bearssl-aarch64>" >&2; exit 2 ;;
esac