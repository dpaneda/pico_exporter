#!/bin/sh
# Regenerate compile_commands.json for clangd. The native build uses one
# uniform flag set for every translation unit, so no compiler wrapper is needed.
set -eu

cd "$(dirname "$0")/.."
DIR=$(pwd)
BEARSSL_INC=${BEARSSL_INC:-build/deps/bearssl/bearssl-0.6/inc}

FLAGS="-std=c11 -Wall -Wextra -O2 -Isrc -Ivendor -Itests -I$BEARSSL_INC"

{
  echo '['
  first=1
  for f in src/*.c tests/*.c; do
    [ $first -eq 1 ] || echo ','
    first=0
    printf '  {"directory": "%s", "file": "%s", "command": "cc %s -c %s"}' \
      "$DIR" "$f" "$FLAGS" "$f"
  done
  echo
  echo ']'
} > compile_commands.json

echo "wrote compile_commands.json ($(grep -c '"file"' compile_commands.json) entries)"
