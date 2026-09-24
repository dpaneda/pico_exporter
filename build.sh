#!/usr/bin/env bash
# Build pico_exporter. Artifacts (everything links against picolibc):
#   bin/pico_exporter                         static x86_64 picolibc (dev/tests,
#                                            built with the host `cc`) -- just
#                                            delegated to `make`.
#   bin/pico_exporter-picolibc-aarch64        static aarch64 picolibc deployable
#                                            (built with aarch64-linux-gnu-gcc).
#                                            crt0/ldscript/triplet are
#                                            target-specific, so this stays a
#                                            dedicated single gcc -flto link here.
#
# This script defines no compile or link flags of its own: it reads them back
# out of the Makefile (`make print-<VAR>`, see the print-% rule there) so the
# two binaries cannot drift apart. What lives here is only what is genuinely
# aarch64-specific: the cross compiler, the picolibc triplet, and the fact that
# every TU goes into one gcc invocation.
#
# Toolchains resolve themselves, no env hunting required -- everything is
# fetched/built into build/deps/ inside the repo (tools/bearssl_env.sh pins the
# tarballs by sha256; nothing outside the repository is touched):
#   picolibc    built on demand into build/deps/picolibc-gnu (aarch64 + x86_64)
# Layout expected under a picolibc root:
#   $PICOLIBC_ROOT/usr/local/picolibc/{aarch64,x86_64}-linux/{include/none,lib/none}
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/tools/bearssl_env.sh"

# picolibc. Defaults to the repo-local pinned install (build/deps/picolibc-gnu,
# built on demand by ensure_picolibc); PICOLIBC_ROOT overrides it, and
# PICOLIBC_ROOT="" (explicitly empty) skips the picolibc targets.
PICOLIBC_ROOT="${PICOLIBC_ROOT-$PICOLIBC_ROOT_DEFAULT}"
PICOLIBC_CC="${PICOLIBC_CC:-aarch64-linux-gnu-gcc}"
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

if [ -n "$PICOLIBC_ROOT" ]; then
  ensure_picolibc "$PICOLIBC_ROOT"

  echo "== static x86_64 picolibc (dev): make =="
  build_bearssl_lib_pico "$BEARSSL_LIB_PICO_HOST" "$HOST_CC" ar
  # The dev binary is entirely the Makefile's job. A non-default PICOLIBC_ROOT
  # also redirects the Makefile at "its" picolibc install. This runs first so
  # that a GW_URL/CAFILE build has already fetched the bundle and generated the
  # trust-anchor header by the time the aarch64 link needs it.
  if [ "$PICOLIBC_ROOT" != "$PICOLIBC_ROOT_DEFAULT" ]; then
    MAKEVARS+=("PICO_ROOT=$PICOLIBC_ROOT/usr/local/picolibc/x86_64-linux")
  fi
  make "${MAKEVARS[@]}"
  if [ "$PICOLIBC_ROOT" != "$PICOLIBC_ROOT_DEFAULT" ]; then
    unset 'MAKEVARS[${#MAKEVARS[@]}-1]'
  fi

  echo "== static aarch64 picolibc (deployable) =="
  # One single-invocation -flto link per target: it is what makes every TU see
  # identical flags (picolibc headers, -D__picolibc__) -- a per-TU mix is what
  # produced __isoc23_strtoll/errno/uname mismatches in the past.
  #
  # Every flag below comes out of the Makefile. Two do not cross the seam:
  # -mstack-protector-guard=global is x86-only (this gcc rejects it), which is
  # why CORE_CFLAGS is what gets read rather than CFLAGS; and $(TA_DEF) carries
  # make-side shell quoting, so it is rebuilt here from the plain TA_DIR and
  # TA_HNAME -- make has already fetched the bundle and generated the header.
  AARCH64_ROOT="$PICOLIBC_ROOT/usr/local/picolibc/aarch64-linux"
  CORE_CFLAGS="$(mk print-CORE_CFLAGS)"
  CPPFLAGS="$(mk print-CPPFLAGS)"
  SRCS="$(mk print-SRCS)"
  PICO_LINK="$(mk print-PICO_LINK PICO_ROOT="$AARCH64_ROOT")"
  PICO_INC="$(mk print-PICO_INC PICO_ROOT="$AARCH64_ROOT")"
  TA_DEF=""
  ta_hname="$(mk print-TA_HNAME)"
  if [ -n "$ta_hname" ]; then
    TA_DEF="-DBG_TA_HEADER=\"$ta_hname\" -I$(mk print-TA_DIR)"
  fi

  build_bearssl_lib_pico "$BEARSSL_LIB_PICO"
  "$PICOLIBC_CC" $CORE_CFLAGS $TA_DEF $CPPFLAGS -D_GNU_SOURCE -D__picolibc__ \
    -I"$PICO_INC" -I"$BEARSSL_INC" \
    $SRCS "$BEARSSL_LIB_PICO" $PICO_LINK \
    -o bin/pico_exporter-picolibc-aarch64
  ls -la bin/pico_exporter-picolibc-aarch64
fi

echo "OK:"
ls -la bin/
size bin/pico_exporter-picolibc-aarch64 2>/dev/null || true