/* fmt_oracle.c - the shared fmt sweep linked against picolibc.
 *
 * Together with tests/fmt_check.inc this re-runs the harness's deterministic
 * sweep with picolibc's printf/strtod in the oracle seat, keeping the decimal
 * layer pinned against the libc it replaced (issue #2) without making that
 * checkout/build part of the ordinary build: tests/picolibc.sh provisions
 * build/deps/picolibc-oracle on demand and compiles this binary.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fmt.h"

#include "fmt_check.inc"

int main(void) { return fmt_check_cmd(); }
