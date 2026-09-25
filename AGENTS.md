# AGENTS.md — pico_exporter internals

This file is the reference for anyone working on the codebase: how the build
works, what every module does, the memory strategy, the test suite, and the
gotchas that have cost real time in the past.

## What this is

`pico_exporter` is a C11, **push-only** system metrics exporter for a Raspberry
Pi. Every 15 s it reads `/proc` + `/sys` + `statvfs`, builds an
`ExportMetricsServiceRequest` protobuf, and POSTs it to a Grafana Cloud OTLP
gateway over TLS. Two hard constraints drive every design decision:

1. **Footprint is the goal.** Resting RSS (between cycles, `smaps_rollup`) is
   28 kB on the Pi (20-32 kB on x86) — see "Memory & footprint". No `malloc` unless the arena is
   exhausted (never in production), plus `popen` in the SYSTEMD=1 build:
   per-cycle data goes to the arena, everything else to `.bss`, the TLS
   session mapping, or a mapping `idle_sleep` drops.
2. **Everything must self-bootstrap.** A fresh clone needs only host base tools
   + network once; BearSSL, picolibc and meson are fetched (sha256-pinned) and
   built into the gitignored `build/deps/`.

Two binary flavors, both statically linked against **picolibc** (no glibc):

- `bin/pico_exporter` — **x86_64**, linked by the Makefile with the host `cc`.
  A production binary like the other one; it is also what the test suite runs
  against, being the one that builds on the dev host.
- `bin/pico_exporter-picolibc-aarch64` — **aarch64 deployable**, linked by
  `build.sh` with `aarch64-linux-gnu-gcc`.

## Layout

```
src/pico_exporter.c   entry, env/flag config, the push cycle loop, cycle log line
src/collectors.[ch]   /proc + /sys + statvfs parsers; one function per metric
                      family; emits text lines (--metrics-once) or msample[]
src/otlp.[ch]         OTLP protobuf encoder (dry-run sizing + backpatching),
                      Sum/Gauge split, first/count chunking
src/push.[ch]         URL parse, Basic auth, TCP connect, HTTP/1.1 request +
                      response drain, keep-alive across batches
src/dns.c             minimal RFC-1035 A-record resolver (UDP, /etc/resolv.conf)
src/bearglue.[ch]     BearSSL client, session/handshake anon page mappings, one suite
src/arena.[ch]        mmap + madvise(MADV_DONTNEED) per-cycle arena
src/idle.[ch]         drop-then-sleep between cycles: evicts code/rodata/handshake
                      state/deep stack with raw madvise, then raw nanosleep
src/pdir.[ch]         getdents64 directory iterator (no opendir, no heap)
src/linux_sock.c      picolibc socket/network syscall shims (aarch64 + x86_64)
srv/                  header stubs picolibc lacks: sys/socket.h, netinet/in.h,
                      sys/utsname.h, sys/sysinfo.h
vendor/               compiled-in trust anchors (bearssl_ta_digicert_g2.h)
tests/run.sh          integration gate driving the harness + fake rootfs
tests/run_tests.c     single harness binary: TLS, wrong-anchor, oversize-record
                      recovery, keep-alive, OTLP encode decode round-trip
tests/fake_root.sh    generates a synthetic /proc//sys tree
tests/sink.py, verify_batch.py   local HTTP sink + OTLP wire decoder
tools/bearssl_env.sh  pinned URLs+sha256 and the fetch/build functions
tools/deps.sh         `make deps` driver (bearssl-host, picolibc, bearssl-pico)
tools/doctor.sh       `make doctor` host-prerequisite preflight
tools/fetch_ta.sh     fetch a trust anchor from a live endpoint (`make CAFILE_URL=`)
tools/gen_ta.sh       render a PEM trust anchor into a vendor/ header
tools/gen_compile_commands.sh  compile_commands.json for clangd
build/                objects, test binaries, self-bootstrapped toolchains (gitignored)
bin/                  built binaries (gitignored)
```

## Build system

### Makefile targets

The user-facing targets are the table in [DEVELOPMENT.md](DEVELOPMENT.md). Two
exist only for the suite: `make test-bin` (`build/tests/run_tests` +
`build/tests/pico_exporter-capped` + `build/tests/pico_exporter-systemd`) and
`make capped` (just the capped one, built with `COLLECT_MAX_SAMPLES=120`).

`make aarch64` runs `build.sh`, which delegates the **x86_64 binary to `make`**
and then does the aarch64 link itself as a **single gcc `-flto` invocation** —
compiling every TU in one command is what keeps all TUs on identical flags
(`-D__picolibc__`, picolibc headers) and avoids the cross-TU libc-mismatch bugs
of the past.

**`build.sh` declares no flags of its own.** It reads them back out of the
Makefile through the `print-%` rule (`make print-CORE_CFLAGS`, `print-CPPFLAGS`,
`print-SRCS`, `print-PICO_LINK PICO_ROOT=<aarch64 root>`, `print-PICO_INC`),
forwarding the same `SYSTEMD`/`INSECURE`/`CAFILE`/`GW_URL` on every query so the
feature defines it compiles with are the ones `make` resolved. The Makefile is
the only place a compile or link flag is written down; what is genuinely
aarch64-only lives in `build.sh` (cross compiler, picolibc triplet, the single
`-flto` invocation). Two values deliberately do not cross the seam:

- `-mstack-protector-guard=global` is x86-only (the aarch64 gcc rejects it),
  which is why `CORE_CFLAGS` — not `CFLAGS` — is the shared variable.
- `$(TA_DEF)` carries make-side shell quoting (`'"header.h"'`), so `build.sh`
  rebuilds that one flag from the plain `print-TA_DIR`/`print-TA_HNAME`.

Regression guard, if you touch either file: a refactor of the build must leave
both binaries **byte-identical** (`sha256sum bin/*`), since it changes no flag.

### Feature toggles

What the knobs do is in [DEVELOPMENT.md](DEVELOPMENT.md); what matters here is
where they land. `SYSTEMD` → `-DENABLE_SYSTEMD`, compiling in
`collect_systemd()` (`popen systemctl list-units`); **off by default** — it is
the only collector that shells out, and it describes the host's service manager
rather than the machine, so the default build omits it and
`build/tests/pico_exporter-systemd` is what keeps it tested. `INSECURE` →
`-DBG_INSECURE_NO_VERIFY`, which swaps in the accept-any X.509 engine and drops
the trust anchors from the binary — `curl -k` semantics.

**Trust-anchor variables:** `CAFILE` is the *user's* input and `TA_BUNDLE` the
PEM actually compiled in (`CAFILE`, or the bundle `GW_URL` fetched). They used
to share the name `CAFILE`, and because a command-line variable overrides a
makefile assignment, `make GW_URL=x CAFILE=y` silently compiled y's anchor
while still fetching x. They are now separate and set together is a hard
`$(error)` — which `build.sh` relies on instead of re-checking.

**Flags stamp:** `make` cannot see `CFLAGS` as a dependency, so
`make INSECURE=1` on a dirty tree would keep stale objects. A force-touched
`build/.flags-stamp` records the effective `CFLAGS` string and is a normal
prerequisite of every object; it only rewrites when the string changes, so
steady-state builds stay no-ops.

### Self-bootstrapping deps

`tools/bearssl_env.sh` pins every download by sha256 and builds into
`build/deps/`:

- **BearSSL** (0.6): source tarball, then three libs — `lib-native`,
  `lib-x86_64-picolibc` (for the x86_64 binary, built with `cc` **and `-flto`** so
  the LTO link can reach into it), `lib-aarch64-picolibc` (built with the cross
  gcc, also `-flto`, plus `-DBR_INT128=0` to drop the `i62` RSA paths).
- **picolibc 1.8.12**: built from the pinned tarball with meson into
  `{aarch64,x86_64}-linux/{include,lib}/none`. Meson itself is a pinned tarball
  run via a PATH shim (never installed system-wide). The host (x86_64) install
  is configured with a generated `cross-x86_64-linux-gnu.txt` mapping the plain
  host tools (`cc`/`ar`/…).

## Runtime

### Cycle (`src/pico_exporter.c`)

- Parse flags, `signal(SIGPIPE, SIG_IGN)` (a write on a server-closed
  keep-alive socket must trigger a reconnect, not a kill), entropy gate
  (`bg_seed()`) when the URL is https.
- Loop:
  1. `collect_all()` into a `struct metrics` backed by the cycle arena;
     append `up = 1`.
  2. Split the `emitted` samples into batches of `BATCH`
     (`otlp_encode` per batch with `first`/`count`), push over **one**
     keep-alive connection (`rw_conn`), reopening lazily if the peer dropped it.
  3. `printf("cycle epoch_s=… samples=… blks=… payloadB=… pushed=true http=200")`.
  4. `metrics_free()` → `arena_reset()` (madvise) → `otlp_buf_reset()` →
     `idle_sleep(INTERVAL)`: evicts the TLS handshake mapping, the stack
     below the sleeping frame, the clean `.rodata`/`.data.rel.ro` pages and
     the whole `.text` except its own page, then `nanosleep`. All raw
     syscalls, so no other code page is touched. See "Memory & footprint".

**The connection is held across cycles, not just across the batches of one
cycle.** A handshake per cycle was 24.5 ms of the Pi's 41 ms CPU budget, more
than the whole collection; the gateway keeps an idle connection well past the
interval (measured >200 s). Because only a failed write reveals a connection
the peer dropped while we slept, each batch gets **two attempts** — without
the retry, every drop would silently cost a batch, which is what the old code
did on any mid-cycle failure. A reopen that is not the process's first
appears as `reopen=N` on the cycle line, and `tests/run.sh` asserts that
several cycles ride one TCP connection (`sink.py` records every accepted
connection in `<file>.conns`).

Resource attributes: `service.name` = `JOB` (default
`integrations/node_exporter`), `service.instance.id` = `INSTANCE` (default
`uname -n`).

### Config surface

The environment table is in the [README](README.md). What it does not carry:

- Flags: `--help`, `--metrics-once` (text dump, no caps/caps report),
  `--dump=<substr>` (samples dump), `--path.rootfs=<dir>` (scrape a fake tree).
- Deprecated/ignored: `ROOTFS` (use `--path.rootfs`; a warning is printed),
  `CAFILE` as a *runtime* variable (anchors are compiled in; ignored with a
  warning — not to be confused with the build-time knob).

### Collectors (`src/collectors.c`)

One function per metric family, in a fixed order (`collect_all`); several are
wrapped in `SCRAPE(name)` which reports `node_scrape_collector_*_seconds` /
`_success` for each. Reads go through `read_proc()`, which uses `open`/`read`
(never stdio) and **reads files to EOF** into a growable buffer carved from
the cycle arena (4 kB to start, doubling; a one-off malloc in the one-shot
modes, which have no arena) — fixed-size slices silently truncate, which is
how a 300-socket `/proc/net/udp` once reported 63. Directory listings go
through `pdir` (`getdents64`), never `opendir`/`readdir`: picolibc's
`fopen`/`opendir` were the only `malloc` callers, so the default build has no
heap page at all.

Output modes:

- **text** (`--metrics-once`): `metrics_line()` appends ready-formatted
  `name{k="v",…} value` lines. Values go through `fmt_float` (shortest
  round-trip via precisions 1..17 against `strtod`).
- **samples** (push/`--dump`): fills `msample{name, labels, nlabels, value}`
  (32 B; `labels` points at exactly `nlabels` pairs carved from the same
  per-cycle storage, NULL when there are none); names/labels are arena-backed
  strings. `*_total` suffix ⇒ OTLP Sum.

Sample budget: `COLLECT_MAX_SAMPLES` (default 8192)/`COLLECT_MAX_LABELS` (8),
with **2 reserved slots** so `up` and the cap self-report
(`node_exporter_dropped_samples_total`) always emit — even in the cycle that
hit the cap. A hit cap is *reported* (`ndropped`/`nlabels_capped` → WARN line
in one-shot modes, extra fields on the cycle line), never swallowed.

Metric families: build_info, own VmRSS, uname, uptime, load, entropy, memory
(meminfo extras), stat (cpu/ctx/intr/forks/procs/boot), disk bytes, filefd,
filesystem, network counters, vmstat, cpufreq, diskstats, pressure, netstat,
sockstat, udp_queue, hwmon, textfile (if `TEXTFILE_DIR`), systemd (if
`ENABLE_SYSTEMD`, i.e. `SYSTEMD=1` — not the default).

### OTLP encoder (`src/otlp.c`)

Hand-rolled protobuf with a **dry-run first pass** that counts bytes, then a
real pass; frames are emitted with 10 reserved length-varint bytes and
backpatched, so there is never a realloc mid-emit. Fixed nesting:

```
ExportMetricsServiceRequest (1) → ResourceMetrics
  resource (1) → KeyValue*: service.name / service.instance.id
  scope_metrics (2) → Metric*
    name (1), gauge (5) or sum (7) → NumberDataPoint*
    (sum only) temporality (2)=2, is_monotonic (3)=1
    NumberDataPoint: attributes (7) KeyValue*, time_unix_nano (3) fixed64,
                     as_double (4) fixed64
```

The encoder reads `msample[]` directly (no per-cycle mirror copy). The OTLP
round-trip in the harness is the wire gate — no frozen golden fixtures.

### Push (`src/push.c`) + DNS (`src/dns.c`)

- `parse_rw_url`, base64 Basic auth, IPv4 `tcp_connect_host` (blocking,
  `SO_RCVTIMEO`).
- DNS: a ~1.5 kB RFC-1035 client — UDP query to the first `/etc/resolv.conf`
  nameserver (then a secondary), first A record wins, **`s_addr` must stay
  network byte order** (a host-order `<<24` bug flipped the IP on LE hosts and
  hung `connect()`).
- `conn_open` for https does the BearSSL handshake once; `conn_push` sends the
  request and drains the exact `Content-Length` so keep-alive works. A write
  error on a dead keep-alive socket surfaces as "not alive" and the loop
  reconnects.

### BearSSL glue (`src/bearglue.c`)

TLS state lives in two anonymous page mappings created on the first
handshake, one client per process: the **session** pages (client context +
record buffer, kept while the keep-alive connection lives) and the
**handshake** page (X.509 context), which `idle_sleep` drops every cycle
because `br_x509_minimal_init` rewrites it before each handshake and
BearSSL, with `BR_OPT_NO_RENEGOTIATION`, only reads it during one (the
harness `fallback` case zero-fills it mid-connection and requires the next
request to succeed). `g_ioc`, the seed and the pointers stay in `.bss`. No
TLS state on the heap: the oversized-record fallback buffer is an `mmap` too.

- One suite: `BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`; one curve:
  `br_ec_p256_m15`; RSA PKCS#1 verify for the ServerKeyExchange.
- **RFC 6066 fragment length** (`BG_MAX_FRAG`, default 2048) sizes the
  session I/O buffer to 2.4 kB instead of the worst-case 16.7 kB. A peer that
  ignores the extension and sends a bigger record fails the handshake with
  `BG_ERR_TOO_LARGE`; `conn_open` then calls `bg_grow_iobuf()` once (moves to a
  full-size anonymous mapping, kept for the process) and retries on a fresh
  connection. A cooperating peer stays at the small buffer forever.
- **Insecure engine** (`BG_INSECURE_NO_VERIFY`): an accept-any x509 context;
  the leaf is still decoded with `br_x509_decoder` so the ServerKeyExchange
  signature can be verified. Bypasses chain/dates/name checks; the compiled-in
  anchors are omitted from the binary.
- The default anchor set comes from `vendor/bearssl_ta_digicert_g2.h`
  (`BG_TA_HEADER`); tests override with `bg_set_ta()`.

### Arena (`src/arena.c`)

1 MiB anonymous `mmap`, bump-allocated, `reset()` = `madvise(base, cap,
MADV_DONTNEED)` + offset 0. Pages are re-faulted next cycle, so arena bytes
cost nothing *at rest* — but every page the cycle touches is a real fault and
a real page while the cycle runs, which is the exporter's true peak.
`metrics_free` also frees any malloc fallback escapes (`heap_samples`).

Two rules the size and the flags encode:

- **Stay under 2 MiB and ask for `MADV_NOHUGEPAGE`.** With transparent
  hugepages in `always` mode (most x86 distro kernels; *not* the deployed Pi,
  which has no THP at all) a ≥2 MiB mapping faults a whole 2 MiB page on first
  touch, so a 113 kB cycle measured 2196 kB peak RSS instead of 264 kB.
- **`arena_extend` / `arena_realloc`** grow the last block in place. The OTLP
  encode buffer is always the arena's last block (encoding runs after
  collection), so each batch of a cycle extends it instead of stranding the
  previous batch's region: 28 kB/cycle of abandoned buffers → ~6 kB.

### picolibc socket shims (`src/linux_sock.c` + `srv/`)

picolibc's linux port has no `<sys/socket.h>` or socket wrappers, so
`src/linux_sock.c` provides `socket/connect/sendto/recvfrom/setsockopt/uname`
via raw `syscall()` with per-arch numbers:

| call | aarch64 | x86_64 |
|---|---|---|
| socket | 198 | 41 |
| connect | 203 | 42 |
| sendto | 206 | 44 |
| recvfrom | 207 | 45 |
| setsockopt | 208 | 54 |
| uname | 160 (newuname) | 63 (struct is 390 bytes) |

plus `sysconf(_SC_CLK_TCK)` and `__errno_location`. Headers it lacks live under
`srv/` (`netinet/in.h`, `sys/socket.h`, `sys/utsname.h`, `sys/sysinfo.h`).

## Measuring memory (read this before trusting a number)

Every figure in this repo has been wrong at least once because of how the
measurement was taken, not because of the code. The traps, in the order they
bite:

- **`VmRSS`/`VmHWM` hide small transients.** The kernel's RSS counters are
  per-CPU and sync in batches of 64 pages, so a spike under ~256 kB never
  reaches `/proc/<pid>/status`. On the Pi, `VmRSS` read 97,386 times over 20 s
  never left 140 kB while the process was faulting 38 pages (152 kB) *every
  cycle*. `VmHWM` does not save you: it is derived from the same counters, and
  it was observed going **down** between reads on the dev host.
  → **Measure a transient with `minflt` (field 10 of `/proc/<pid>/stat`).**
  Page faults are exact and unbatched; multiply by 4096. Poll it in a tight
  Python loop reading the already-open fd, not with `awk` per iteration --
  spawning a process per sample is slow enough to miss the window.
- **`/proc/<pid>/smaps_rollup` is exact.** It walks the page tables instead
  of reading the batched counters, so it is the number to quote for a
  resting figure. `tests/run.sh` gates on it.
- **Refaulting one file page maps its neighbours.** The kernel's fault-around
  (16 pages) brings back up to 64 kB of a file mapping on a single
  instruction fetch, which is why `idle_sleep` keeps its own page instead of
  dropping it: measured 84 kB vs 4 kB resident text.
- **Transparent hugepages inflate anonymous mappings ~20x.** With THP in
  `always` mode a ≥2 MiB anonymous mapping faults a whole 2 MiB page on first
  touch: the 4 MiB arena made a 113 kB cycle measure 2196 kB of peak RSS.
  Check `/sys/kernel/mm/transparent_hugepage/enabled` and
  `AnonHugePages:` in `/proc/<pid>/smaps` before believing any anonymous
  number. The deployed Pi kernel has no THP at all, the x86 dev host has it on
  -- which is why **the two disagree by 10x and the Pi is the one that
  counts.**
- **`VmRSS` is not one thing.** `RssFile` (the binary's text/rodata pages) is
  clean page cache the kernel drops for free under pressure; `RssAnon`
  (`.bss`, stack, heap, arena) is the part that actually has to go somewhere.
  Quote both.
- **`/proc/<pid>/smaps` needs privileges** for a process you do not own, so
  the per-mapping breakdown is root-only on the Pi. `status` and `stat` are
  world-readable and carry everything above.
- **Attribute `.text` with a linker map, not with `nm` prefixes.** LTO renames
  and inlines: grouping by symbol name put a third of BearSSL under
  `pico_exporter`. Relink with `-Wl,-Map=` and classify the input sections.

## Memory & footprint

Since the idle RSS drop (`idle_sleep` between cycles, session/handshake TLS
mappings, `pdir`/no-stdio reads), resting RSS is measured with
`smaps_rollup` while the process sleeps between cycles, on the x86_64 dev
host:

| | before | after, http sink | after, real TLS gateway |
|---|---|---|---|
| text (r-xp) | 84 kB | 4 kB (only `idle_sleep`'s page) | 4 kB |
| RW file mapping (rodata + dirty data page) | 20 kB | 4 kB (the dirty data page) | 4 kB |
| `.bss` anon pages | 4 kB (http) | 0 (small `.bss` fits in the data page) | 0 |
| TLS anon mappings | n/a | none | 8 kB (session pages; handshake page evicted) |
| `[heap]` | 4 kB | 0 | 0 |
| `[stack]` | 16 kB | 12 kB (env/argv + `main`/`push_loop` frames) | 12-16 kB |
| **Rss total** | **128 kB** | **20-24 kB** | **28-32 kB** |

Per cycle: 16 minor faults, measured by the `tests/run.sh` gate (fake
rootfs, http; a real host with a bigger arena footprint faults more). Arena
refaults are the bulk: the kernel's fault-around maps 16 pages per fault, so
the ~21 text pages and 4 rodata pages come back in about 2-3 faults.

**Pi (aarch64, TLS, live gateway), measured 2026-09-25 after two 60 s
intervals: `smaps_rollup` Rss 28 kB, Anonymous 20 kB** (`status`: VmRSS 28,
RssAnon 20, RssFile 8, VmHWM 132 — the HWM is the cycle peak). Per mapping:
text 4 kB, RW file mapping 8 kB, TLS session mapping 8 kB, stack 8 kB. The
extra RW page versus x86 is aarch64's first RW page, which holds `.eh_frame`
plus a 4-byte writable `.except_unordered`, so `PCEIL(_pid_base)` keeps it.
Before this work the same process read 124 kB (92 file + 32 anon).
Procedure, run after two full intervals (`smaps_rollup` is the figure to
quote; `status` may lag):

```bash
P=$(pidof pico_exporter)
sudo awk '/^(Rss|Anonymous):/{print}' /proc/$P/smaps_rollup
grep -E "VmRSS|RssAnon|RssFile" /proc/$P/status
```

| Mapping | RSS at rest | Why it stays |
|---|---|---|
| text | 4 kB | the page holding `idle_sleep`; the other ~20 pages refault each cycle |
| rodata/data | 4 kB (8 on aarch64) | the dirty page: `.rodata` tail, `.data.rel.ro`, `__tls_space`, `.data`, small `.bss`; aarch64 also keeps the `.eh_frame`/`.except_unordered` page |
| TLS session mapping | 8 kB | `br_ssl_client_context` + record buffer, alive across the keep-alive sleep |
| stack | 8-12 kB | env/auxv page(s) plus the `main`/`push_loop` frame; deeper pages are dropped |
| heap | 0 | no `malloc` unless the arena is exhausted (never in production), plus `popen` in the SYSTEMD=1 build |
| TLS handshake mapping | 0 | dropped each idle, refilled on the next handshake |
| arena | 0 | `MADV_DONTNEED` each cycle (unchanged) |

`.text` by origin, from the linker map (previous measurement; text size no
longer sets the resting footprint, only per-cycle refault cost and file
size):

| | `.text` | `.rodata` |
|---|---|---|
| BearSSL | 30.4 kB | 7.7 kB (6.1 kB of it T0 bytecode) |
| pico_exporter | 26.2 kB | — |
| picolibc | 19.1 kB | 6.3 kB |

Rules that follow from the measurement:

- **`.text` no longer sets the resting footprint**: it is dropped before each
  sleep and refaulted in a handful of faults thanks to fault-around at the
  next cycle. Its size still
  costs per-cycle faults and file size, nothing at rest. `aligned(4096)` on
  `idle_sleep` adds up to 4 kB of file padding per binary, never resident.
- The I/O-buffer fallback (`bg_grow_iobuf`) is safe at runtime *because* the
  full buffer is only allocated when a peer needs it. A cipher-suite fallback
  would have to **link both implementations** — numerically the thing being
  saved — so it can only be a compile-time knob.
- Crypto offers ~5.5 kB if you are willing to narrow interop (X25519 ~3.5 kB,
  ChaCha20-Poly1305 ~2 kB).
- Things ruled out with evidence: integer-only printf (printed `*float*` and
  corrupted every value), server-key pinning (cert rotation ⇒ outages), ECDSA
  (chain is RSA), BearSSL context trimming (needs a fork for a few hundred
  bytes), session resumption (both gateways --
  `prometheus-us-central1.grafana.net`, the harness default, and
  `otlp-gateway-prod-us-central-0.grafana.net`, production -- send an
  **empty** session id in ServerHello, so there is no server-side session
  cache to resume against; they resume only via RFC 5077 tickets, which
  BearSSL 0.6 does not implement. Measured 2026-09-25 with
  `run_tests resume [URL]` and confirmed with
  `openssl s_client -tls1_2 -reconnect -no_ticket` (6/6 "New"). The harness
  `resume` probe re-checks it and prints a NOTE if a gateway ever starts
  issuing ids).
- **The compiler-flag space is exhausted; measured, on the aarch64 link.**
  `-Oz` is *larger* than `-Os` (+128 B) and `-O2` much larger (+6.6 kB).
  `-fno-ident`, `-fmerge-all-constants`, `-fno-math-errno`, `-fipa-icf`,
  `-fno-stack-protector` and `-Wl,-z,norelro` each change the output by
  **zero bytes**. `-flto-partition=one` saves 256 B of `.text` and
  `-Wl,--build-id=none` 128 B of file, neither crossing a page.
  `-Wl,--icf=all` is gold/lld only and does not link. Trimming picolibc's
  meson options (`fast-strcmp=false`, `single-thread=true`,
  `atomic-ungetc=false`, `assert-verbose=false`) buys 704 B of `.text` in
  exchange for changed libc locking and errno semantics — not taken. The one
  flag that did pay was `-fno-unwind-tables`, and it is in.
- **Avoiding `%g` at the call sites does not drop the float printf code.**
  picolibc's tinystdio has one `vfprintf` that handles every conversion, so
  the `dtoa` path is linked as soon as anything calls `printf`. Replacing
  `fmt_float` with an integer format saved **64 bytes**, measured. Only
  picolibc's separate integer-only variant removes it, and that is the option
  ruled out above.
- **Anything that must survive the sleep goes to `.bss` or the session
  mapping; anything dead at idle goes to a mapping `idle_sleep` drops.**
  Never put live state in the handshake mapping or below `push_loop`'s
  frame expecting it to persist: both are zero-filled by the next idle.
  `idle_stack_floor()` must run before the first `idle_sleep()`; the drop
  is skipped while the floor is unset.

## Testing

How to run it is in [DEVELOPMENT.md](DEVELOPMENT.md); `make clean` runs at the
end because artifacts are disposable, while `build/deps/` is kept. What the
suite actually covers:

- **Fake rootfs** (`tests/fake_root.sh` → `tests/.fake`): `--metrics-once`
  assertions on names/labels/**values** for every export, a 300-socket
  `/proc/net/udp` to prove whole-table reads, cap self-report via
  `build/tests/pico_exporter-capped` (`COLLECT_MAX_SAMPLES=120`,
  `SYSTEMD=0`), and — against `build/tests/pico_exporter-systemd`, since the
  default build has no systemd collector — systemd count consistency with the
  live host.
- **Harness** `build/tests/run_tests` subcommands:
  - `tls` — live endpoint: valid chain, 405 on bare GET, stale-clock rejection;
  - `tls-bad` — wrong trust anchor must fail (62);
  - `fallback` — oversized-record recovery (`bg_test_force_too_large` seam);
    also proves the TLS handshake mapping is dead mid-connection (zero-fills
    it, requires the next request to still succeed);
  - `resume [URL]` — a probe, not a pass/fail gate: reports whether the
    gateway issues a TLS session id (it does not; see "Things ruled out"),
    and `tests/run.sh` turns a newly issued id into a NOTE line;
  - `keepalive` — 3 POSTs on one connection vs `tests/sink.py`;
  - `encode TS NRES FIRST COUNT [k=v…]` — OTLP encode/decode round-trip using
    an **independent protobuf walker** (no golden fixtures).
- **Sink decode** (`verify_batch.py`): totals frames/series; the one-cycle test
  proves `pushed series == dumped samples + up`.
- TLS cases need network; they `SKIP` cleanly when offline. The python3-based
  sink/push cases `SKIP` when `python3` is absent.
- **Resting-footprint gate** (`tests/run.sh`, sampled while the process
  sleeps between cycles against the http sink): `smaps_rollup` Rss <= 32 kB,
  no `[heap]` mapping, minor faults over two cycles <= 320 — all gated on the
  exporter still being alive (`kill -0`), so a crash fails loudly instead of
  passing on absent files.
- **Layout invariant** (`tests/run.sh`, before the fake-root run, on
  `bin/pico_exporter` and, if built, the aarch64 binary): `readelf` must show
  no relocations and no writable section other than `.data.rel.ro` inside
  the RW range `idle_sleep` drops, `[PCEIL(.rodata), PFLOOR(min(.tls_space,
  .data)))`, so a picolibc or linker-script change cannot silently put
  written data under `MADV_DONTNEED`.

## Deployment

There is no deploy target: the build produces a static binary and installing it
is the host's business (`contrib/pico_exporter.service` is the reference unit).
The one lesson worth carrying into whatever installs it — **a binary that links
is not a binary that pushes.** Verify by waiting out a full interval and reading
a `cycle ... pushed=true http=200` line from the log, not by checking that the
process started; and keep the outgoing binary around so a rollback is a copy
rather than a rebuild. After deploying, take the `smaps_rollup` measurement
in "Memory & footprint" above and update the Pi figure in this file.

## Conventions & gotchas

- **No comments unless they explain a non-obvious decision** — the existing
  code comments are all such justification comments; match that tone.
- **No `malloc` unless the arena is exhausted (never in production), plus
  `popen` in the SYSTEMD=1 build** (`tests/run.sh` fails on a `[heap]`
  mapping). Per-cycle data goes to the arena; state that must
  survive the sleep goes to `.bss` or the TLS session mapping; state dead at
  idle goes to a mapping `idle_sleep` drops. Read `/proc`//`/sys` with
  `open`/`read` and directories with `pdir`, never stdio/dirent.
- **C11, `-std=c11`.** Compile every TU with identical flags: `-D_GNU_SOURCE`,
  `-D__picolibc__`, `-Isrv`, picolibc + BearSSL include dirs. Mixing them once
  produced `__isoc23_strtoll`/errno/uname mismatches between TUs.
- **Stack canary**: the x86_64 build needs `-mstack-protector-guard=global`.
  The host gcc defaults to the glibc TLS canary (`%fs:0x28`) but picolibc seeds
  a *global* `__stack_chk_guard`; the mismatch reads a phantom smash (triggered
  by any `/proc` file ≥ 4095 B) and `read_proc` aborts. The aarch64 gcc rejects
  the option and needs nothing.
- **Network byte order matters in `s_addr`** — copy the 4 RDATA bytes, do not
  shift-shift-OR.
- **`idle_sleep` must stay a self-contained page.** No calls out (not even
  libc), no stack protector, `aligned(4096)`; a `printf` or a helper call
  there makes another text page resident for the whole sleep.
  `-mstack-protector-guard=global` would otherwise add a canary check;
  `no_stack_protector` needs GCC >= 11 (older compilers warn and keep the
  canary, which costs nothing at rest).
- **The Pi's `strace` is 32-bit (armhf)** and mis-decodes aarch64 syscalls —
  useless for diagnosing the deployable.
- **Gateway debugging**: a mangled `GW_PASS` makes the gateway answer **404**,
  not a TLS/`/otlp/v1/metrics` bug. To test manually, reuse creds from
  `/proc/<pid>/environ` or `systemctl show-environment`, not a hand-rolled
  extractor.
- **Do not flip the crypto suite default** to a ChaCha20/X25519-only build
  casually — the conservative suite is what keeps the binary working against
  unknown (incl. FIPS-mode) endpoints.
- **`SC_DEBUG`/whichever `--collector.*` flags from the reference exporter are
  gone** — config is env-based (`GW_URL`/`GW_USER`/`GW_PASS` for the
  gateway, plain `JOB`/`INSTANCE`/`INTERVAL`/`BATCH`/`TEXTFILE_DIR` for the
  rest) plus the four flags listed above.
- Keep `bin/` free of test artifacts (test binaries live in `build/tests/`).
