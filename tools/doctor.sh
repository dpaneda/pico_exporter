#!/usr/bin/env bash
# tools/doctor.sh - host-prerequisite preflight for pico_exporter builds.
# Pins a fresh-clone failure down to a named tool with an install hint, instead
# of a mid-fetch `command not found` inside tools/deps.sh.
#
#   make doctor
#
# Env overrides, same as the build: CC, PICOLIBC_CC; PICOLIBC_ROOT="" disables
# the picolibc targets entirely (their tools stop being required). Exits 1 when
# anything required is missing.
set -uo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/tools/bearssl_env.sh"

CC="${CC:-cc}"
PICOLIBC_CC="${PICOLIBC_CC:-aarch64-linux-gnu-gcc}"
PICOLIBC_ROOT="${PICOLIBC_ROOT-$PICOLIBC_ROOT_DEFAULT}"

fail=0
report() { # report <tool> <purpose> <apt-package>
  if command -v "$1" >/dev/null 2>&1; then
    printf '  ok      %-22s %s\n' "$1" "$2"
  else
    printf '  MISSING %-22s %s\n' "$1" "$2"
    printf '          install with: sudo apt install %s\n' "$3"
    fail=1
  fi
}

echo "pico_exporter doctor: host prerequisites"

echo
echo "core build:"
report "$CC"       "host C compiler"           gcc
report "make"      "build driver"              make
report "ar"        "static archives (BearSSL)" binutils
report "curl"      "pinned tarball downloads"  curl
report "tar"       "tarball unpack"            tar
report "sha256sum" "download integrity check"  coreutils

echo
echo "tests:"
report "python3"   "local sink + wire decoder" python3

if [ -n "$PICOLIBC_ROOT" ]; then
  echo
  echo "picolibc (disable with PICOLIBC_ROOT=; meson is bundled, no system install):"
  report "ninja"        "picolibc build"               ninja-build
  report "$PICOLIBC_CC" "aarch64 cross gcc"            gcc-aarch64-linux-gnu
else
  echo "picolibc targets disabled (PICOLIBC_ROOT empty): ninja and $PICOLIBC_CC not required"
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "all prerequisites present"
else
  echo "missing tools listed above; install them, then re-run make doctor"
fi
exit "$fail"