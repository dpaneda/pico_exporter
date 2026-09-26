#!/usr/bin/env bash
# tests/picolibc.sh - the fmt sweep against picolibc, provisioned on demand.
#
# The suite's `fmt` case pins the decimal layer against whichever libc the
# harness itself links (glibc since the freestanding switch). This script is
# the forgotten half of that check: it fetches + builds a picolibc install
# under build/deps/picolibc-oracle (host x86_64 only), compiles
# tests/fmt_oracle.c + src/fmt.c against it into
# build/tests/run_tests-picolibc, and runs the identical deterministic sweep
# with picolibc's printf/strtod in the oracle seat. Nothing is wired into
# `make` or the ordinary build -- fetching picolibc for every clone would be
# paying a libc dependency nobody links anymore, just to keep one test.
# tests/run.sh turns provisioning failures into SKIP lines.
#
#   bash tests/picolibc.sh          # build if missing, then run the oracle
#
# Exit 0:   the oracle ran (its own exit code carries the sweep verdict).
# Exit 77:  provisioning unavailable (offline, missing ninja/python3) -> SKIP.
# Other:    provisioning worked but the run itself failed -> FAIL.
#
# (The provisioner recipe and its pins are the tools/bearssl_env.sh
# ensure_picolibc()/ensure_meson() code the freestanding switch deleted,
# narrowed to the single host target the oracle needs.)
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
ORAC="$DIR/build/deps/picolibc-oracle"

PICOLIBC_VER="1.8.12"
PICOLIBC_TGZ_SHA256="64e8c412e1c40fa6eb1a72d2b5cdbcbfe6ceca4cbea454edbad54557ffc747fa"
PICOLIBC_URL="https://github.com/picolibc/picolibc/releases/download/${PICOLIBC_VER}/picolibc-${PICOLIBC_VER}.tar.xz"

MESON_VER="1.12.0"
MESON_TGZ_SHA256="88afe0c20e52030218924ac37d0c81c59b4b5f3ae3752c8c6d7470c7d365886c"
MESON_URL="https://github.com/mesonbuild/meson/releases/download/${MESON_VER}/meson-${MESON_VER}.tar.gz"

ROOT="$ORAC/root/usr/local/picolibc/x86_64-linux"
INC="$ROOT/include/none"
LIB="$ROOT/lib/none"
BIN="$DIR/build/tests/run_tests-picolibc"

# meson needs its picolibc cross file even on the host: it is what pins
# crt0-default/ldscript/link-args to the linux flavor the install layout
# (lib/none) matches.
CROSS="$ORAC/cross-x86_64-linux-gnu.txt"

skip() { echo "SKIP: fmt picolibc oracle ($1)"; exit 77; }

for t in cc tar sha256sum curl python3 ninja; do
  command -v "$t" >/dev/null 2>&1 || skip "missing $t"
done

mkdir -p "$ORAC" "$DIR/build/tests"

# --- meson (picolibc's build tool), run from its pinned tarball ------------
PY="$ORAC/meson/meson-$MESON_VER/meson.py"
if [ ! -f "$PY" ]; then
  echo "== fetching meson $MESON_VER =="
  rm -rf "$ORAC/meson"
  mkdir -p "$ORAC/meson"
  curl -fsSL --max-time 300 -o "$ORAC/meson.tgz" "$MESON_URL" \
    || skip "could not fetch meson"
  echo "$MESON_TGZ_SHA256  $ORAC/meson.tgz" | sha256sum -c - >/dev/null \
    || skip "meson sha256 mismatch"
  tar xzf "$ORAC/meson.tgz" -C "$ORAC/meson" || skip "could not unpack meson"
  rm -f "$ORAC/meson.tgz"
fi

# --- picolibc source + x86_64-linux install --------------------------------
if [ ! -f "$LIB/libc.a" ]; then
  echo "== fetching picolibc $PICOLIBC_VER =="
  if [ ! -d "$ORAC/src/picolibc-$PICOLIBC_VER" ]; then
    rm -rf "$ORAC/src"
    mkdir -p "$ORAC/src"
    curl -fsSL --max-time 600 -o "$ORAC/picolibc.txz" "$PICOLIBC_URL" \
      || skip "could not fetch picolibc"
    echo "$PICOLIBC_TGZ_SHA256  $ORAC/picolibc.txz" | sha256sum -c - >/dev/null \
      || skip "picolibc sha256 mismatch"
    tar xJf "$ORAC/picolibc.txz" -C "$ORAC/src" || skip "could not unpack picolibc"
    rm -f "$ORAC/picolibc.txz"
  fi

  # Same generated cross file the pre-freestanding build used: upstream's
  # cross-x86_64-linux-gnu.txt wants x86_64-linux-gnu-{ar,nm,strip,...} that
  # plain Debian hosts do not ship, so the host tools are mapped in instead.
  cat > "$CROSS" <<'EOF'
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

  echo "== building picolibc x86_64-linux (first time only) =="
  rm -rf "$ORAC/build-x86_64-linux-gnu" "$ORAC/root"
  mkdir -p "$ORAC/build-x86_64-linux-gnu"
  (
    cd "$ORAC/build-x86_64-linux-gnu"
    python3 "$PY" setup \
      -Dsemihost=false -Dos-linux=true -Dtmpdir=/tmp/ \
      -Dmultilib-exclude=x32 \
      -Dprefix=/usr/local \
      -Dincludedir=picolibc/x86_64-linux/include \
      -Dlibdir=picolibc/x86_64-linux/lib \
      -Dbuild-type-subdir=none \
      -Dtests=false -Dnative-tests=false \
      --cross-file "$CROSS" \
      "$ORAC/src/picolibc-$PICOLIBC_VER" \
      || exit 1
    ninja || exit 1
    DESTDIR="$ORAC/root" ninja install || exit 1
  ) || skip "picolibc build failed"
fi

for f in crt0-linux.o libc.a liblinux.a picolibc_linux.ld; do
  [ -f "$LIB/$f" ] || skip "picolibc install incomplete (no $LIB/$f)"
done

# Compile + run the sweep. The link mirrors the old picolibc link line
# (crt0 + libc + liblinux + picolibc_linux.ld, -nostdlib -static): the only
# libc-abi bits the sweep needs are the ones this provides.
echo "== compiling fmt oracle against picolibc =="
if ! cc -std=c11 -Os -ffunction-sections -fdata-sections -Wall -Wextra \
    -U_FORTIFY_SOURCE -D__picolibc__ \
    -I"$INC" -I"$DIR/src" -I"$DIR/tests" \
    "$DIR/tests/fmt_oracle.c" "$DIR/src/fmt.c" \
    "$LIB/crt0-linux.o" \
    -Wl,--start-group "$LIB/libc.a" "$LIB/liblinux.a" -Wl,--end-group \
    -Wl,--build-id=none -Wl,-z,max-page-size=0x1000 \
    -Wl,-T,"$LIB/picolibc_linux.ld" \
    -lgcc -nostdlib -nostartfiles -static -no-pie \
    -o "$BIN"; then
  skip "compiling the picolibc oracle failed"
fi

exec "$BIN"
