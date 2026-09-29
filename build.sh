#!/usr/bin/env bash
# Build pico_exporter. Artifacts:
#   bin/pico_exporter          static x86_64 freestanding (dev/tests, built by
#                              the host `cc`) -- just delegated to `make`.
#   bin/pico_exporter-aarch64  static aarch64 freestanding deployable,
#                              built with aarch64-linux-gnu-gcc.
#
# This script defines no compile or link flags of its own: it reads them back
# out of the Makefile (`make print-<VAR>`, see the print-% rule there) so the
# two binaries cannot drift apart. What lives here is only what is genuinely
# aarch64-specific: the cross compiler and the short sequence below.
#
# Nothing is fetched but BearSSL (pinned by tools/bearssl_env.sh into
# build/deps/bearssl): the in-repo runtime in src/start.c, src/freestand.c and
# src/pico.ld replaces what libc used to provide -- the cycle arena (src/arena.c)
# is the allocator, so there is no heap implementation at all -- which makes the
# only outside package this link needs the cross gcc itself.
#
# Why two TUs compile *outside* the single command: src/start.c and
# src/freestand.c (FS_OBJS in the Makefile) define libc
# entry-point names and run before the stack guard is seeded, so they take
# the Makefile's $(FS_FLAGS) (-fno-builtin, -fno-stack-protector); a single
# gcc invocation cannot carry per-TU flags. The dev build compiles them as
# their own objects via the Makefile's FS_CFLAGS override and this script
# replicates that exact command line, then hands the .o files to the
# all-TUs -flto link with the remaining sources.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/tools/bearssl_env.sh"

# The aarch64 cross compiler. It supplies declarations only (its glibc
# headers); nothing from that libc lands in the binary.
AARCH64_CC="${AARCH64_CC:-aarch64-linux-gnu-gcc}"
HOST_CC="${CC:-cc}"

# Feature toggles. Only forwarded, never defaulted here: the Makefile owns the
# defaults, the mutual-exclusion check and the trust-anchor fetch/generate.
#   SYSTEMD=1   add node_systemd_units collection (off by default)
#   INSECURE=1  skip X.509 validation, trust any certificate (BG_INSECURE_NO_VERIFY)
#   CAFILE=...  PEM cert(s) to replace the compiled-in DigiCert G2 root
#   GW_URL=...  discover those anchors from an endpoint (fetch_ta.sh, TOFU)
MAKEVARS=()
for v in SYSTEMD INSECURE CAFILE GW_URL; do
  if [ -n "${!v+x}" ]; then MAKEVARS+=("$v=${!v}"); fi
done

# Everything below runs relative to the repo (the include paths are).
cd "$DIR"

# Same variable set for every query, so what build.sh compiles with is exactly
# what `make` resolved -- feature defines included.
mk() { make -s "$@" "${MAKEVARS[@]}"; }

echo "== static x86_64 (dev): make =="
build_bearssl_lib_lto "$BEARSSL_LIB_HOST" "$HOST_CC" ar "$BEARSSL_EXTRA_HOST"
# The dev binary is entirely the Makefile's job. This runs first so that a
# GW_URL/CAFILE build has already fetched the bundle and generated the
# trust-anchor header by the time the aarch64 link needs it.
make "${MAKEVARS[@]}"

echo "== static aarch64 (deployable) =="
# Every flag below comes out of the Makefile. Two do not cross the seam:
# -mstack-protector-guard=global is x86-only (this gcc defaults to the same
# global __stack_chk_guard instead), which is why CORE_CFLAGS is what gets
# read rather than CFLAGS; and $(TA_DEF) carries make-side shell quoting, so
# it is rebuilt here from the plain TA_DIR and TA_HNAME -- make has already
# fetched the bundle and generated the header.
CORE_CFLAGS="$(mk print-CORE_CFLAGS)"
CPPFLAGS="$(mk print-CPPFLAGS)"
FS_FLAGS="$(mk print-FS_FLAGS)"
FS_OBJS="$(mk print-FS_OBJS)"
SRCS="$(mk print-SRCS)"
STATIC_LINK="$(mk print-STATIC_LINK)"
TA_DEF=""
ta_hname="$(mk print-TA_HNAME)"
if [ -n "$ta_hname" ]; then
  TA_DEF="-DBG_TA_HEADER=\"$ta_hname\" -I$(mk print-TA_DIR)"
fi

build_bearssl_lib_lto "$BEARSSL_LIB_AARCH64" "$AARCH64_CC" aarch64-linux-gnu-ar

# The runtime TUs, compiled exactly like the Makefile's FS_CFLAGS objects
# (-fno-builtin/-fno-stack-protector on top of the shared CORE_CFLAGS), then
# the single -flto link over everything else.
# One single-invocation link for the main TUs is what makes them see
# identical flags -- a per-TU mix is what produced libc-mismatch failures in
# the past (see AGENTS.md).
#
# One deliberate difference: the runtime TUs are compiled *without* -flto.
# They are the libc entry points, and as LTO IR the cross gcc's -flto=auto
# partitioning drops their definitions from the final link -- the link failed
# with "undefined reference to memset" (from collect_cpufreq) while the host
# gcc, which keeps them, linked fine. Compiling them outside the single
# invocation is exactly what they are for: they must be real objects.
CORE_FS_CFLAGS="${CORE_CFLAGS//-flto=auto/}"
mkdir -p bin build/fs
fs_o=()
for f in $FS_OBJS; do
  c="${f%.o}.c"
  o="build/fs/$(basename "$f")"
  "$AARCH64_CC" $CORE_FS_CFLAGS $FS_FLAGS $CPPFLAGS -D_GNU_SOURCE \
    -D__PICO_FREESTAND__ -I"$BEARSSL_INC" -c "$c" -o "$o"
  fs_o+=("$o")
done
SRCS_MAIN=()
for s in $SRCS; do
  case "$s" in src/start.c|src/freestand.c) continue ;; esac
  SRCS_MAIN+=("$s")
done

"$AARCH64_CC" $CORE_CFLAGS $TA_DEF $CPPFLAGS -D_GNU_SOURCE \
  -D__PICO_FREESTAND__ -I"$BEARSSL_INC" \
  "${SRCS_MAIN[@]}" "${fs_o[@]}" "$BEARSSL_LIB_AARCH64" $STATIC_LINK \
  -o bin/pico_exporter-aarch64

echo "OK:"
ls -la bin/pico_exporter-aarch64
size bin/pico_exporter-aarch64 2>/dev/null || true
