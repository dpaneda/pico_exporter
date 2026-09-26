#!/usr/bin/env bash
# tools/doctor.sh - host-prerequisite preflight for pico_exporter builds.
# Pins a fresh-clone failure down to a named tool with an install hint, instead
# of a mid-fetch `command not found` inside tools/deps.sh.
#
#   make doctor
#
# Env overrides, same as the build: CC, AARCH64_CC. Exits 1 when anything
# required is missing.
set -uo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/tools/bearssl_env.sh"

CC="${CC:-cc}"
AARCH64_CC="${AARCH64_CC:-aarch64-linux-gnu-gcc}"

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
report "readelf"   "layout invariant gate"     binutils

echo
echo "aarch64 deployable:"
report "$AARCH64_CC"                   "aarch64 cross gcc (libc-free link)" gcc-aarch64-linux-gnu
report "aarch64-linux-gnu-readelf"     "aarch64 layout invariant gate"      binutils-aarch64-linux-gnu

echo
echo "optional (fmt-vs-picolibc oracle; tests/picolibc.sh SKIPs without it):"
if command -v ninja >/dev/null 2>&1; then
  printf '  ok      %-22s %s\n' "ninja" "picolibc build for the fmt oracle"
else
  printf '  MISSING %-22s %s\n' "ninja" "fmt-vs-picolibc oracle will SKIP"
  printf '          install with: sudo apt install %s\n' ninja-build
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "all prerequisites present"
else
  echo "missing tools listed above; install them, then re-run make doctor"
fi
exit "$fail"