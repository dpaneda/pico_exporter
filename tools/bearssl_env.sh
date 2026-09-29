#!/usr/bin/env bash
# Shared dependency locations/pins for pico_exporter. Sourced by build.sh,
# tools/deps.sh, tools/doctor.sh, and (via tools/deps.sh) the Makefile.
#
# Self-bootstrapping: everything fetched or built lands inside the repository
# directory ($BEARSSL_DIR/build/deps, gitignored). A fresh clone only needs the
# host base tools (cc/curl/tar/sha256sum/make, and for the aarch64 link an
# aarch64-linux-gnu cross gcc) plus one-time network access to download the
# pinned tarball. Nothing outside the repo is touched.
#
# BearSSL is the repo's single external dependency. The libc that used to be
# picolibc is now in-repo (src/start.c + src/freestand.c + src/pico.ld),
# built against the compilers that are already here, so there is
# no libc bootstrap at all. (musl and glibc cross builds were removed
# 18/19-Sep-2026; picolibc itself, and meson with it, on 26-Sep-2026.)

BEARSSL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PICO_DEPS="$BEARSSL_DIR/build/deps"

# --- BearSSL -------------------------------------------------------------
BEARSSL_VER="0.6"
BEARSSL_TGZ_SHA256="6705bba1714961b41a728dfc5debbe348d2966c117649392f8c8139efc83ff14"
BEARSSL_URL="https://bearssl.org/bearssl-${BEARSSL_VER}.tar.gz"
BEARSSL_CACHE="$PICO_DEPS/bearssl"
BEARSSL_SRC="$BEARSSL_CACHE/bearssl-${BEARSSL_VER}"
BEARSSL_TGZ="$BEARSSL_CACHE/bearssl-${BEARSSL_VER}.tar.gz"
BEARSSL_INC="$BEARSSL_SRC/inc"
BEARSSL_LIB_NATIVE="$BEARSSL_CACHE/lib-native/libbearssl.a"   # brssl tool only
BEARSSL_LIB_AARCH64="$BEARSSL_CACHE/lib-aarch64/libbearssl.a"
BEARSSL_LIB_HOST="$BEARSSL_CACHE/lib-x86_64/libbearssl.a"

# Ensure the BearSSL source tree exists.
ensure_bearssl_src() {
  if [ ! -d "$BEARSSL_SRC" ]; then
    mkdir -p "$BEARSSL_CACHE"
    if [ ! -f "$BEARSSL_TGZ" ]; then
      echo "== fetching BearSSL $BEARSSL_VER =="
      curl -fsSL --max-time 120 -o "$BEARSSL_TGZ" "$BEARSSL_URL"
    fi
    echo "$BEARSSL_TGZ_SHA256  $BEARSSL_TGZ" | sha256sum -c - >/dev/null
    tar xzf "$BEARSSL_TGZ" -C "$BEARSSL_CACHE"
  fi
}

# ensure_bearssl_lib <out-lib-path> [cc] [ar]
# -fno-unwind-tables on top of -fno-asynchronous-unwind-tables: neither flag
# is enough on its own, and with -flto the tables travel in the IR -- GCC
# records per-TU flags, so no amount of flag-juggling on the final link
# removes them. BearSSL alone was 6.9 kB of .eh_frame, 62% of the section, for
# code that is pure C and never unwinds.
BEARSSL_CFLAGS="-W -Wall -Os -ffunction-sections -fdata-sections -fno-asynchronous-unwind-tables -fno-unwind-tables -U_FORTIFY_SOURCE"
# BR_INT128/BR_UMUL128 pick the i62 RSA/i31 modpow paths (bigger and, on the
# A53, not faster). Disabling them selects the i31 implementations, saving
# ~1.5 KB of .text in the full (TLS) build.
BEARSSL_CFLAGS_NO128="$BEARSSL_CFLAGS -DBR_INT128=0"
# A cached .a is only valid for the flags that produced it. Without this a
# tree that already had build/deps/ kept a stale library after a CFLAGS edit,
# silently undoing the change.
bearssl_lib_is_current() {   # <out-lib> <cflags>
  [ -f "$1" ] || return 1
  [ "$(cat "$1.cflags" 2>/dev/null)" = "$2" ]
}

build_bearssl_lib() {
  local out="$1" cc="${2:-cc}" ar="${3:-ar}" work
  bearssl_lib_is_current "$out" "$BEARSSL_CFLAGS_NO128" && return 0
  rm -f "$out"
  ensure_bearssl_src
  work="$(dirname "$out")/src"
  mkdir -p "$(dirname "$out")"
  [ -d "$work" ] || cp -r "$BEARSSL_SRC" "$work"
  # Default conf adds -fPIC; we link statically, so no PIC (smaller code) and
  # per-function sections so --gc-sections can drop unused BearSSL code.
  make -C "$work" -j"$(nproc)" clean >/dev/null 2>&1 || :
  make -C "$work" -j"$(nproc)" CC="$cc" AR="$ar" LD="$cc" \
    CFLAGS="$BEARSSL_CFLAGS_NO128" build/libbearssl.a >/dev/null
  cp "$work/build/libbearssl.a" "$out"
  printf '%s' "$BEARSSL_CFLAGS_NO128" > "$out.cflags"
}

# x86_64 only, and not a stylistic choice: gcc 16 miscompiles BearSSL's
# AES-NI key schedule. br_aes_x86ni_keysched_enc ends up with a movaps to a
# 16-byte stack slot the prologue never aligned, so the first TLS handshake
# dies on SIGSEGV. Seen in production on delorean with gcc 16.2.1, and it is
# not our link's doing: it reproduces on an unmodified HEAD build, with
# BearSSL compiled without -flto, and the same source links and runs on the
# aarch64 Pi. The buggy path is selected by the #ifndef-guarded BR_AES_X86NI,
# so -D0 drops it and the portable br_aes_ct64_bitslice_* is used instead
# (x86_64-only, and --gc-sections then discards the AES-NI text). BearSSL's
# intrinsics are the only reason a per-target extra exists at all, so this is
# where the aarch64/x86_64 difference is allowed to live: the Pi keeps its
# hardware AES and stays byte-for-byte the link it already runs.
BEARSSL_EXTRA_HOST="-DBR_AES_X86NI=0"

# build_bearssl_lib_lto <out-lib-path> [cc] [ar] [extra-cflags]: BearSSL for
# one of the -flto service links. Must be built with the *same* compiler as the
# final link and with -flto so the link-time optimizer can strip TLS record
# modes (CBC/CHAPOL/CCM) that the single AEAD suite never uses. A different
# -flto producer still links, it just re-expands everything. Defaults (with no
# cc/ar) build the aarch64 deployable lib with $AARCH64_CC /
# aarch64-linux-gnu-ar.
build_bearssl_lib_lto() {
  local out="$1"
  local cc="${2:-${AARCH64_CC:-aarch64-linux-gnu-gcc}}"
  local ar="${3:-${AARCH64_AR:-aarch64-linux-gnu-ar}}"
  local extra="${4:-}"
  local flags="$BEARSSL_CFLAGS_NO128 -flto $extra"
  local work
  bearssl_lib_is_current "$out" "$flags" && return 0
  rm -f "$out"
  ensure_bearssl_src
  work="$(dirname "$out")/src"
  mkdir -p "$(dirname "$out")"
  [ -d "$work" ] || cp -r "$BEARSSL_SRC" "$work"
  make -C "$work" -j"$(nproc)" clean >/dev/null 2>&1 || :
  make -C "$work" -j"$(nproc)" CC="$cc" AR="$ar" LD="$cc" \
    CFLAGS="$flags" build/libbearssl.a >/dev/null
  cp "$work/build/libbearssl.a" "$out"
  printf '%s' "$flags" > "$out.cflags"
}
