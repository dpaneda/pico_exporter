# Development

Notes on building, testing and deploying pico_exporter. For runtime usage and
configuration, see the [README](README.md).

## Prerequisites

Host tools: `cc`, `make`, `curl`, `tar`, `sha256sum` and — for the aarch64
deployable — an `aarch64-linux-gnu` cross gcc (Debian:
`gcc-aarch64-linux-gnu`). `make doctor` names any missing tool with its install
hint before you hit a mid-build failure.

The binaries are freestanding: compiled with the host/cross cc's glibc headers
as declarations only, and linked `-nostdlib -static` against the in-repo
runtime (`src/start.c`, `src/freestand.c`, `src/alloc.c`, `src/pico.ld`). The
single external dependency left is BearSSL, fetched into the gitignored
`build/deps/`, pinned by sha256.

## Build targets

| Target | Result |
|---|---|
| `make` | `bin/pico_exporter` — static x86_64 binary |
| `make debug` | `-O0 -g3` dev build |
| `make aarch64` | `bin/pico_exporter-aarch64` — static aarch64 deployable |
| `make deps` | pre-fetch/build BearSSL into `build/deps/` |
| `make doctor` | host-prerequisite preflight |
| `make test` | run the full gate, then drop all its artifacts |
| `make clean` | drop build outputs, keep cached toolchains |
| `make distclean` | drop `build/` entirely |

Both flavors are static freestanding links (no glibc, no libc at rest) with the
same flag set (`-Os`, LTO, per-function sections, plus `-fno-builtin
-fno-stack-protector` on the three runtime TUs — see build.sh's header for
why they compile outside the single -flto command). Both are production
binaries; the test suite runs against the x86_64 one because that is the one
that builds on the dev host.

## Feature toggles

Compile-time, read by both `make` and `build.sh`:

| Knob | Default | Effect |
|---|---|---|
| `SYSTEMD=1` | off (0) | add `node_systemd_units` (fork/execs `systemctl` via raw syscalls) |
| `INSECURE=1` | off (0) | skip X.509 validation — lab endpoints only, enables MITM |
| `GW_URL=https://gateway:443/` | none | compile in the anchor that endpoint serves, instead of the default DigiCert G2 |

Anchors are always compiled in, never fetched at runtime. The test harness
forces `INSECURE=0` and the default anchor, because its wrong-anchor case
depends on real validation.

## Test

`make test` builds everything, runs `tests/run.sh` and cleans up after itself.
`make test-bin` builds the harness binaries without running them. What the
suite covers is in [AGENTS.md](AGENTS.md); cases needing network or `python3`
SKIP cleanly when either is missing. Nothing outside `build/deps/bearssl` is
fetched, and the only libc the suite links is the host's own (the harness is an
ordinary glibc binary; the service-shaped test binaries are freestanding).

## Source layout

Per-file detail is in [AGENTS.md](AGENTS.md).

```
src/        entry, collectors, OTLP encoder, push, DNS, BearSSL glue, arena
            (the only allocator) + the freestanding runtime: start.c
            (crt/environ), freestand.c (syscall wrappers, mem/str, popen_sh),
            pico.ld
srv/        minimal socket/in.h/utsname.h stubs shadowing the host headers
vendor/     embedded trust anchors
tests/      integration harness + fake-rootfs fixtures (generated, no golden files)
tools/      self-bootstrap deps (bearssl_env.sh, deps.sh), doctor.sh,
            trust-anchor helpers (fetch_ta.sh, gen_ta.sh), gen_compile_commands.sh
build/      build outputs + self-bootstrapped BearSSL (gitignored)
bin/        built binaries (gitignored)
```
