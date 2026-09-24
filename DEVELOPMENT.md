# Development

Notes on building, testing and deploying pico_exporter. For runtime usage and
configuration, see the [README](README.md).

## Prerequisites

Host tools: `cc`, `make`, `curl`, `tar`, `sha256sum`, `python3`, `ninja` and —
for the aarch64 deployable — an `aarch64-linux-gnu` cross gcc (Debian:
`gcc-aarch64-linux-gnu`). `make doctor` names any missing tool with its install
hint before you hit a mid-build failure.

Everything else is downloaded into the repo: BearSSL, picolibc and meson
self-bootstrap into the gitignored `build/deps/`, every tarball pinned by
sha256. No toolchain archaeology.

## Build targets

| Target | Result |
|---|---|
| `make` | `bin/pico_exporter` — static x86_64 binary |
| `make debug` | `-O0 -g3` dev build |
| `make aarch64` | `bin/pico_exporter-picolibc-aarch64` — static aarch64 deployable |
| `make deps` | pre-fetch/build every toolchain into `build/deps/` |
| `make doctor` | host-prerequisite preflight |
| `make test` | run the full gate, then drop all its artifacts |
| `make clean` | drop build outputs, keep cached toolchains |
| `make distclean` | drop `build/` entirely |

Both flavors are statically linked against **picolibc** (no glibc) with the
same flags (`-Os`, LTO, per-function sections). Both are production
binaries; the test suite runs against the x86_64 one because that is the one
that builds on the dev host.

## Feature toggles

Compile-time, read by both `make` and `build.sh`:

| Knob | Default | Effect |
|---|---|---|
| `SYSTEMD=1` | off (0) | add `node_systemd_units` (shells out to `systemctl`) |
| `INSECURE=1` | off (0) | skip X.509 validation — lab endpoints only, enables MITM |
| `GW_URL=https://gateway:443/` | none | compile in the anchor that endpoint serves, instead of the default DigiCert G2 |

Anchors are always compiled in, never fetched at runtime. The test harness
forces `INSECURE=0` and the default anchor, because its wrong-anchor case
depends on real validation.

## Test

`make test` builds everything, runs `tests/run.sh` and cleans up after itself.
`make test-bin` builds the harness binaries without running them. What the
suite covers is in [AGENTS.md](AGENTS.md); cases needing network or `python3`
SKIP cleanly when either is missing.

## Source layout

Per-file detail is in [AGENTS.md](AGENTS.md).

```
src/        entry, collectors, OTLP encoder, push, DNS, BearSSL glue, arena
srv/        picolibc socket/network header stubs (aarch64 + x86_64)
vendor/     embedded trust anchors
tests/      integration harness + fake-rootfs fixtures (generated, no golden files)
tools/      self-bootstrap deps (bearssl_env.sh, deps.sh), doctor.sh,
            trust-anchor helpers (fetch_ta.sh, gen_ta.sh), gen_compile_commands.sh
build/      build outputs + self-bootstrapped toolchains (gitignored)
bin/        built binaries (gitignored)
```
