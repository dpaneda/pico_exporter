#!/usr/bin/env bash
# tools/deps.sh - self-bootstrap the build dependencies into build/deps/
# (inside the repo, gitignored). Nothing outside the repository is touched.
#
#   tools/deps.sh bearssl-host    BearSSL lib for the x86_64 picolibc link (-flto, host cc)
#   tools/deps.sh bearssl-pico     BearSSL lib for the aarch64 picolibc link (-flto)
#   tools/deps.sh picolibc         picolibc libc, aarch64 + x86_64 (pinned; meson comes along)
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/tools/bearssl_env.sh"

case "${1:-}" in
  bearssl-host)  build_bearssl_lib_pico "$BEARSSL_LIB_PICO_HOST" "${CC:-cc}" ar ;;
  bearssl-pico)  PICOLIBC_CC="${PICOLIBC_CC:-aarch64-linux-gnu-gcc}" \
                    build_bearssl_lib_pico "$BEARSSL_LIB_PICO" ;;
  picolibc)      ensure_picolibc "${PICOLIBC_ROOT:-}" ;;
  *) echo "usage: tools/deps.sh <bearssl-host|bearssl-pico|picolibc>" >&2; exit 2 ;;
esac