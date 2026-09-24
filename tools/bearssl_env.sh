#!/usr/bin/env bash
# Shared dependency locations/pins for pico_exporter. Sourced by build.sh,
# tools/deps.sh, and (via tools/deps.sh) the Makefile.
#
# Self-bootstrapping: everything fetched or built lands inside the repository
# directory ($BEARSSL_DIR/build/deps, gitignored). A fresh clone only needs the
# host base tools (cc/python3/curl/tar/sha256sum/make/ninja and, for the
# aarch64 picolibc, an aarch64-linux-gnu cross gcc) plus one-time network access
# to download the pinned tarballs. Nothing outside the repo is touched.
#
# Everything links against picolibc -- the x86_64 dev/tests build uses a host
# picolibc install built with the plain `cc`, the aarch64 deployable uses a
# picolibc install built with aarch64-linux-gnu-gcc.
#
# Every download is pinned by sha256: BearSSL's is stable, picolibc's is a
# named GitHub release, and meson only exists to configure the picolibc build.
# (The musl aarch64 cross toolchain was removed 18-Sep-2026; the glibc native
# dev build 19-Sep-2026. Everything is picolibc now.)

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
BEARSSL_LIB_NATIVE="$BEARSSL_CACHE/lib-native/libbearssl.a"
BEARSSL_LIB_PICO="$BEARSSL_CACHE/lib-aarch64-picolibc/libbearssl.a"
BEARSSL_LIB_PICO_HOST="$BEARSSL_CACHE/lib-x86_64-picolibc/libbearssl.a"

# --- picolibc libc ----------------------------------------------------------
# Built from the pinned release tarball, then DESTDIR-installed under
# $root/usr/local/picolibc/<triplet>/{include,lib}/none:
#   aarch64-linux  -> aarch64 deployable (Debian aarch64-linux-gnu cross gcc)
#   x86_64-linux   -> host dev/test builds (plain `cc`)
#   meson setup options mirror the working layout:
#     -Dbuild-type-subdir=none  -> {include,lib}/none, also skips the .specs
#                                  install (which would write into the system
#                                  gcc dir), and DESTDIR stages the install.
PICOLIBC_VER="1.8.12"
PICOLIBC_TGZ_SHA256="64e8c412e1c40fa6eb1a72d2b5cdbcbfe6ceca4cbea454edbad54557ffc747fa"
PICOLIBC_URL="https://github.com/picolibc/picolibc/releases/download/${PICOLIBC_VER}/picolibc-${PICOLIBC_VER}.tar.xz"
PICOLIBC_SRC="$PICO_DEPS/picolibc-src"
PICOLIBC_ROOT_DEFAULT="$PICO_DEPS/picolibc-gnu"

# The upstream cross-x86_64-linux-gnu.txt wants x86_64-linux-gnu-{ar,nm,strip,
# as,objcopy} (with the Debian cross packages only the -gcc half is present),
# so the host picolibc is configured with this generated file mapped onto the
# plain host tools (cc/ar/...). host_cpu_family 'x86_64' aliases to the same
# 'x86' machine dir in picolibc's meson.build.
PICOLIBC_HOST_CROSS="$PICO_DEPS/cross-x86_64-linux-gnu.txt"
picolibc_write_host_cross() {
  cat > "$PICOLIBC_HOST_CROSS" <<'EOF'
[binaries]
c = 'cc'
cpp = 'c++'
ar = 'ar'
as = 'as'
nm = 'nm'
strip = 'strip'
objcopy = 'objcopy'
exe_wrapper = 'env'

[host_machine]
system = 'linux'
cpu_family = 'x86_64'
cpu = 'x86_64'
endian = 'little'

[properties]
skip_sanity_check = true
link_spec = '--build-id=none'
crt0_default = 'crt0-linux'
oslib_default = 'linux'
linkerscript_default_c = 'picolibc_linux.ld'
linkerscript_default_cpp = 'picolibcpp_linux.ld'
target_c_args = ['-static', '-fno-pic', '-fno-PIE', '-nostdlib', '-nostartfiles', '-Wl,--build-id=none']
default_flash_addr = '0x00100000'
default_flash_size = '0x3ff00000'
default_ram_addr   = '0x40000000'
default_ram_size   = '0x3fff00000'
EOF
}

# --- meson (only needed to configure the picolibc build) -----------------
# Run from the pinned source tarball via its own meson.py behind a tiny PATH
# shim, so nothing is installed system-wide.
MESON_VER="1.12.0"
MESON_TGZ_SHA256="88afe0c20e52030218924ac37d0c81c59b4b5f3ae3752c8c6d7470c7d365886c"
MESON_URL="https://github.com/mesonbuild/meson/releases/download/${MESON_VER}/meson-${MESON_VER}.tar.gz"
MESON_ROOT="$PICO_DEPS/meson"
MESON_PY="$MESON_ROOT/meson-${MESON_VER}/meson.py"

# --- BearSSL source + per-target static libs -----------------------------
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
# is enough on its own (see PICOLIBC_EXTRA_CFLAGS below), and with -flto the
# tables travel in the IR -- GCC records per-TU flags, so no amount of
# flag-juggling on the final link removes them. BearSSL alone was 6.9 kB of
# .eh_frame, 62% of the section, for code that is pure C and never unwinds.
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
  if [ "$(basename "$work")" != "src" ]; then :; fi
  # Default conf adds -fPIC; we link statically, so no PIC (smaller code) and
  # per-function sections so --gc-sections can drop unused BearSSL code.
  make -C "$work" -j"$(nproc)" clean >/dev/null 2>&1 || :
  make -C "$work" -j"$(nproc)" CC="$cc" AR="$ar" LD="$cc" \
    CFLAGS="$BEARSSL_CFLAGS_NO128" build/libbearssl.a >/dev/null
  cp "$work/build/libbearssl.a" "$out"
  printf '%s' "$BEARSSL_CFLAGS_NO128" > "$out.cflags"
}

# build_bearssl_lib_pico <out-lib-path> [cc] [ar]: BearSSL for a picolibc
# link. Must be built with the *same* compiler as the final link and with -flto
# so the link-time optimizer can strip TLS record modes (CBC/CHAPOL/CCM) that
# the single AEAD suite never uses. A different -flto producer breaks the
# lto-wrapper stage of the picolibc link. Defaults (with no cc/ar) build the
# aarch64 deployable lib with $PICOLIBC_CC / aarch64-linux-gnu-ar.
build_bearssl_lib_pico() {
  local out="$1"
  local cc="${2:-${BEARSSL_PICO_CC:-$PICOLIBC_CC}}"
  local ar="${3:-${BEARSSL_PICO_AR:-aarch64-linux-gnu-ar}}"
  local work
  bearssl_lib_is_current "$out" "$BEARSSL_CFLAGS_NO128 -flto" && return 0
  rm -f "$out"
  ensure_bearssl_src
  work="$(dirname "$out")/src"
  mkdir -p "$(dirname "$out")"
  [ -d "$work" ] || cp -r "$BEARSSL_SRC" "$work"
  make -C "$work" -j"$(nproc)" clean >/dev/null 2>&1 || :
  make -C "$work" -j"$(nproc)" CC="$cc" AR="$ar" LD="$cc" \
    CFLAGS="$BEARSSL_CFLAGS_NO128 -flto" build/libbearssl.a >/dev/null
  cp "$work/build/libbearssl.a" "$out"
  printf '%s' "$BEARSSL_CFLAGS_NO128 -flto" > "$out.cflags"
}

# --- meson (picolibc build tool) ------------------------------------------
ensure_meson() {
  if [ ! -f "$MESON_PY" ]; then
    rm -rf "$MESON_ROOT"
    mkdir -p "$MESON_ROOT"
    echo "== fetching meson $MESON_VER =="
    curl -fsSL --max-time 300 -o "$MESON_ROOT/meson.tgz" "$MESON_URL"
    echo "$MESON_TGZ_SHA256  $MESON_ROOT/meson.tgz" | sha256sum -c - >/dev/null
    tar xzf "$MESON_ROOT/meson.tgz" -C "$MESON_ROOT"
    rm -f "$MESON_ROOT/meson.tgz"
  fi
  [ -f "$MESON_PY" ] || { echo "meson not found: $MESON_PY" >&2; exit 1; }
  if [ ! -x "$MESON_ROOT/bin/meson" ]; then
    mkdir -p "$MESON_ROOT/bin"
    printf '#!/bin/sh\nexec "${PYTHON:-python3}" "%s/meson.py" "$@"\n' \
      "$(dirname "$MESON_PY")" > "$MESON_ROOT/bin/meson"
    chmod +x "$MESON_ROOT/bin/meson"
  fi
}

# --- picolibc libc install ------------------------------------------------
# ensure_picolibc [root]: installs the aarch64-linux and x86_64-linux picolibc
# targets under $root (default: $PICOLIBC_ROOT_DEFAULT). Only builds the
# targets that are missing; a full install makes the function a no-op.
# Extra compile flags for picolibc itself, fed to meson as the built-in
# c_args: drop the .eh_frame its 975 objects carry for unwinding that a
# C-only, exception-free binary never performs. Both flags are required and
# in this order of stubbornness -- on aarch64 -fasynchronous-unwind-tables is
# on by default and implies -funwind-tables, so -fno-unwind-tables alone is
# silently undone (measured: the section did not move until the async flag
# was added too).
PICOLIBC_EXTRA_CFLAGS="-fno-unwind-tables -fno-asynchronous-unwind-tables -U_FORTIFY_SOURCE"

ensure_picolibc() {
  local root="${1:-$PICOLIBC_ROOT_DEFAULT}"
  local cc="${PICOLIBC_CC:-aarch64-linux-gnu-gcc}"
  local a64_inc="$root/usr/local/picolibc/aarch64-linux/include/none"
  local a64_lib="$root/usr/local/picolibc/aarch64-linux/lib/none"
  local x86_inc="$root/usr/local/picolibc/x86_64-linux/include/none"
  local x86_lib="$root/usr/local/picolibc/x86_64-linux/lib/none"
  # Same reasoning as bearssl_lib_is_current: an install cached from a
  # different flag string is not the install this tree asked for.
  local stamp="$root/.picolibc-cflags"
  if [ "$(cat "$stamp" 2>/dev/null)" != "$PICOLIBC_EXTRA_CFLAGS" ]; then
    [ -d "$root/usr" ] && echo "== picolibc flags changed, rebuilding =="
    rm -rf "$root/usr"
  fi
  [ -d "$a64_inc" ] && [ -f "$a64_lib/libc.a" ] \
    && [ -d "$x86_inc" ] && [ -f "$x86_lib/libc.a" ] \
    && { printf '%s' "$PICOLIBC_EXTRA_CFLAGS" > "$stamp"; return 0; }

  if [ ! -d "$PICOLIBC_SRC/scripts" ]; then
    mkdir -p "$PICO_DEPS"
    echo "== fetching picolibc $PICOLIBC_VER =="
    curl -fsSL --max-time 600 -o "$PICO_DEPS/picolibc.txz" "$PICOLIBC_URL"
    echo "$PICOLIBC_TGZ_SHA256  $PICO_DEPS/picolibc.txz" | sha256sum -c - >/dev/null
    rm -rf "$PICOLIBC_SRC"
    mkdir -p "$(dirname "$PICOLIBC_SRC")"
    tar xJf "$PICO_DEPS/picolibc.txz" -C "$(dirname "$PICOLIBC_SRC")"
    rm -f "$PICO_DEPS/picolibc.txz"
    mv "$(dirname "$PICOLIBC_SRC")/picolibc-${PICOLIBC_VER}" "$PICOLIBC_SRC"
  fi
  command -v ninja >/dev/null 2>&1 || {
    echo "picolibc build needs ninja" >&2
    exit 1
  }
  ensure_meson

  if [ ! -d "$a64_inc" ] || [ ! -f "$a64_lib/libc.a" ]; then
    command -v "$cc" >/dev/null 2>&1 || {
      echo "aarch64 picolibc build needs \$PICOLIBC_CC (${cc}); install e.g. gcc-aarch64-linux-gnu" >&2
      exit 1
    }
    echo "== building picolibc aarch64-linux =="
    local work="$PICOLIBC_SRC/build-aarch64-linux-gnu"
    rm -rf "$work"
    mkdir -p "$work"
    (
      cd "$work"
      PATH="$MESON_ROOT/bin:$PATH" "$PICOLIBC_SRC/scripts/do-aarch64-linux-gnu-configure" \
        -Dprefix=/usr/local \
        -Dincludedir=picolibc/aarch64-linux/include \
        -Dlibdir=picolibc/aarch64-linux/lib \
        -Dbuild-type-subdir=none \
        -Dtests=false -Dnative-tests=false \
        -Dc_args="$PICOLIBC_EXTRA_CFLAGS" \
        >/dev/null
      ninja
      DESTDIR="$root" ninja install
    )
  fi

  if [ ! -d "$x86_inc" ] || [ ! -f "$x86_lib/libc.a" ]; then
    picolibc_write_host_cross
    echo "== building picolibc x86_64-linux =="
    local work="$PICOLIBC_SRC/build-x86_64-linux-gnu"
    rm -rf "$work"
    mkdir -p "$work"
    (
      cd "$work"
      PATH="$MESON_ROOT/bin:$PATH" meson setup \
        -Dsemihost=false -Dos-linux=true -Dtmpdir=/tmp/ \
        -Dmultilib-exclude=x32 \
        -Dprefix=/usr/local \
        -Dincludedir=picolibc/x86_64-linux/include \
        -Dlibdir=picolibc/x86_64-linux/lib \
        -Dbuild-type-subdir=none \
        -Dtests=false -Dnative-tests=false \
        -Dc_args="$PICOLIBC_EXTRA_CFLAGS" \
        --cross-file "$PICOLIBC_HOST_CROSS" \
        "$PICOLIBC_SRC" >/dev/null
      ninja
      DESTDIR="$root" ninja install
    )
  fi
  printf '%s' "$PICOLIBC_EXTRA_CFLAGS" > "$stamp"
}