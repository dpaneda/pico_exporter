#!/usr/bin/env bash
# Integration tests for pico_exporter against a synthetic fake rootfs.
# Asserts against the C binary's --metrics-once output, checks push behaviour
# against a local HTTP sink, and gates the OTLP wire format with the encode/decode
# round-trip in tests/run_tests.c: no test depends on frozen golden fixtures.
#
# The connection checks (TLS, wrong anchor, oversized-record recovery, keepalive,
# OTLP round-trip) all run through one harness binary, build/tests/run_tests.
set -uo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$DIR/bin/pico_exporter"
ROOT="$DIR/tests/.fake"
HARNESS="$DIR/build/tests/run_tests"

fail=0

if [ ! -x "$BIN" ]; then
  echo "binary missing, building..."
  make -C "$DIR" all test-bin >/dev/null
fi

# idle_sleep drops [PCEIL(.rodata), PFLOOR(min(__tls_space, __data_start)))
# with MADV_DONTNEED. A written page there would silently revert to the file
# image, so no writable section other than .data.rel.ro may intersect it, and
# .data.rel.ro is only clean because a static non-PIE link has no relocations.
layout_check() { # layout_check <bin> <readelf>
  local bin="$1" re="$2" out
  if ! "$re" -rW "$bin" | grep -q "There are no relocations in this file"; then
    echo "FAIL: layout invariant ($bin): binary has dynamic relocations"
    fail=1; return
  fi
  if out=$("$re" -SW "$bin" | sed 's/\[ *\([0-9]*\)\]/\1/' | awk '
    function hex(s,   i, v) {
      v = 0; s = tolower(s)
      for (i = 1; i <= length(s); i++) v = v * 16 + index("0123456789abcdef", substr(s, i, 1)) - 1
      return v
    }
    $1 ~ /^[0-9]+$/ && NF >= 8 {
      name = $2; addr = hex($4); size = hex($6)
      if (name == ".rodata") ro = addr
      if (name == ".tls_space") ts = addr
      if (name == ".data") dt = addr
      if ((name == ".tdata" || name == ".tbss" || name == ".data") && (tl == "" || addr < tl)) tl = addr
      if ($8 ~ /W/ && size > 0) { n++; wn[n] = name; wa[n] = addr; we[n] = addr + size }
    }
    END {
      if (ro == "" || dt == "") { print "no .rodata or .data section"; exit 1 }
      top = (ts != "") ? (ts < dt ? ts : dt) : tl
      lo = int((ro + 4095) / 4096) * 4096
      hi = int(top / 4096) * 4096
      bad = 0
      for (i = 1; i <= n; i++)
        if (wn[i] != ".data.rel.ro" && wa[i] < hi && we[i] > lo) {
          printf "%s [0x%x,0x%x) ", wn[i], wa[i], we[i]; bad = 1
        }
      printf "[0x%x,0x%x)", lo, hi
      exit bad
    }'); then
    echo "PASS: layout invariant ($bin): no writable section in the evicted rodata range $out"
  else
    echo "FAIL: layout invariant ($bin): writable section in the evicted rodata range: $out"
    fail=1
  fi
}
if command -v readelf >/dev/null; then
  layout_check "$BIN" readelf
else
  echo "SKIP: layout invariant ($BIN): readelf not found"
fi
A64="$DIR/bin/pico_exporter-picolibc-aarch64"
if [ -f "$A64" ]; then
  if command -v aarch64-linux-gnu-readelf >/dev/null; then
    layout_check "$A64" aarch64-linux-gnu-readelf
  else
    echo "SKIP: layout invariant ($A64): aarch64-linux-gnu-readelf not found"
  fi
fi

bash "$DIR/tests/fake_root.sh" "$ROOT"

"$BIN" --path.rootfs="$ROOT" --metrics-once >"$DIR/tests/.M.txt" 2>"$DIR/tests/.metrics.log"
M="$(cat "$DIR/tests/.M.txt")"
echo "debug M lines=$(printf '%s' "$M" | wc -l) load1=$(printf '%s' "$M" | grep -ac 'node_load1') sysd=$(printf '%s' "$M" | grep -ac 'node_systemd_units{')" >&2
if [ -z "$M" ]; then
  echo "FAIL: empty --metrics-once output"; cat "$DIR/tests/.metrics.log"; exit 1
fi

check() { # check <desc> <grep-pattern>
  cnt=$(printf '%s' "$M" | grep -acE "$2")
  if [ "$cnt" -gt 0 ]; then
    echo "PASS: $1"
  else
    echo "FAIL: $1"
    fail=1
  fi
}

refute() { # refute <desc> <grep-pattern>
  cnt=$(printf '%s' "$M" | grep -acE "$2")
  if [ "$cnt" -eq 0 ]; then
    echo "PASS: $1"
  else
    echo "FAIL: $1 (pattern unexpectedly matched: $2)"
    fail=1
  fi
}

# --- cpu (values use C's shortest round-trip fmt) ---
check "exporter rss positive"     '^node_exporter_resident_memory_bytes [1-9][0-9]*$'
check "cpu aggregate"             'node_cpu_seconds_total\{mode="user"\} (1e\+01|10\.0)'
check "cpu idle"                  'node_cpu_seconds_total\{mode="idle"\} (5e\+02|500)'
check "cpu scaling cur"           'node_cpu_scaling_frequency_hertz\{chip="cpu0"\} (1\.2e\+09|1200000000)'
check "cpu scaling max"           'node_cpu_scaling_frequency_max_hertz\{chip="cpu0"\} (1\.2e\+09|1200000000)'
check "cpu scaling min"           'node_cpu_scaling_frequency_min_hertz\{chip="cpu0"\} (6e\+08|600000000)'
check "cpu cpufreq cur"           'node_cpufreq_frequency_hertz\{chip="cpu0"\} (1\.2e\+09|1200000000)'
check "cpu governor"              'node_cpufreq_scaling_governor\{chip="cpu0",governor="ondemand"\} 1'

# --- load ---
check "load1"                     'node_load1 0\.42'
check "load5"                     'node_load5 0\.51'
check "load15"                    'node_load15 0\.58'

# --- memory ---
check "mem total"                 'node_memory_MemTotal_bytes 1024000000'
check "mem free"                  'node_memory_MemFree_bytes 204800000'
check "mem available"             'node_memory_MemAvailable_bytes 512000000'
check "mem swap total"            'node_memory_SwapTotal_bytes 102400000'
check "mem swap free"             'node_memory_SwapFree_bytes 97280000'

# --- vmstat ---
check "vmstat free pages"         'node_vmstat_nr_free_pages 52394'
check "vmstat zone active anon"   'node_vmstat_nr_zone_active_anon 5244'
check "vmstat pgpgin"             'node_vmstat_pgpgin 1234567'
check "vmstat pswpin"             'node_vmstat_pswpin 123'

# --- stat ---
check "ctx switches"              'node_context_switches_total 1234567'
check "interrupts"                'node_intr_total 12345678'
check "boot time"                 'node_boot_time_seconds 1788600000'
check "forks"                     'node_forks_total 77881'
check "procs running"             'node_procs_running 2'
check "procs blocked"             'node_procs_blocked 0'

# --- filefd ---
check "filefd allocated"          'node_filefd_allocated 1024'
check "filefd maximum"            'node_filefd_maximum 4096'

# --- entropy ---
check "entropy avail"             'node_entropy_available_bits 512'
check "entropy pool"              'node_entropy_pool_size_bits 4096'

# --- netstat ---
check "udp datagrams"             'node_netstat_Udp_InDatagrams 9000'
check "udp out"                   'node_netstat_Udp_OutDatagrams 9001'
check "tcp curr estab"            'node_netstat_Tcp_CurrEstab 8'
check "tcp in segs"               'node_netstat_Tcp_InSegs 54321'

# --- sockstat ---
check "sockstat sockets used"     'node_sockstat_sockets_used 10'
check "tcp inuse"                 'node_sockstat_TCP_inuse 6'
check "udp inuse"                 'node_sockstat_UDP_inuse 1'

# --- udp queues ---
check "udp queues tx"             'node_udp_queues\{queue="tx"\} (16|16\.0)'
check "udp queues rx"             'node_udp_queues\{queue="rx"\} (32|32\.0)'

# A /proc table larger than the read buffer must be read whole, not truncated.
# With the old fixed 8 kB buffer and char *arr[64] this reported 63 of 300
# sockets -- silently, on any host with more than 63 of them.
BIGROOT="$DIR/tests/.fake_big"
rm -rf "$BIGROOT"; mkdir -p "$BIGROOT/proc/net"
{
  echo "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
  for i in $(seq 1 300); do
    printf "%5d: 00000000:0035 00000000:0000 07 00000001:00000002 00:00000000 00000000     0        0 %d\n" \
      "$i" "$((10000 + i))"
  done
} > "$BIGROOT/proc/net/udp"
BIGSZ="$(wc -c < "$BIGROOT/proc/net/udp")"
BIGTX="$("$BIN" --path.rootfs="$BIGROOT" --metrics-once 2>/dev/null |
         awk '/node_udp_queues\{queue="tx"\}/{print $2}')"
BIGRX="$("$BIN" --path.rootfs="$BIGROOT" --metrics-once 2>/dev/null |
         awk '/node_udp_queues\{queue="rx"\}/{print $2}')"
if [ "$BIGTX" = "3e+02" ] && [ "$BIGRX" = "6e+02" ]; then
  echo "PASS: ${BIGSZ}-byte /proc/net/udp read whole (300 sockets, tx=300 rx=600)"
else
  echo "FAIL: large /proc/net/udp truncated (${BIGSZ} B: tx=$BIGTX want 3e+02, rx=$BIGRX want 6e+02)"
  fail=1
fi
rm -rf "$BIGROOT"

# The textfile collector turns exposition format back into samples, so the
# cases worth pinning are the ones the format allows and a naive split gets
# wrong: a trailing timestamp, a '}' inside a label value, and leading blanks.
TFDIR="$DIR/tests/.textfile"
rm -rf "$TFDIR"; mkdir -p "$TFDIR"
cat > "$TFDIR/unit.prom" <<'PROM'
# HELP tf_labelled Comment lines carry no sample
# TYPE tf_labelled gauge
tf_labelled{sensor="Temp Salón"} 26.53
tf_plain 42
tf_timestamped{sensor="x"} 7 1790012806000
tf_brace_in_label{sensor="raro}dentro"} 3.5
  tf_indented{a="b"} 1
tf_unterminated{sensor="oops
tf_novalue{a="b"}
PROM
echo "tf_must_not_be_read 1" > "$TFDIR/ignored.txt"

TF="$(TEXTFILE_DIR="$TFDIR" "$BIN" --path.rootfs="$ROOT" --dump= 2>/dev/null)"
tfcheck() { # tfcheck <desc> <grep-pattern>
  if printf '%s\n' "$TF" | grep -qE "$2"; then
    echo "PASS: $1"
  else
    echo "FAIL: $1 (no match: $2)"
    fail=1
  fi
}
tfrefute() { # tfrefute <desc> <grep-pattern>
  if printf '%s\n' "$TF" | grep -qE "$2"; then
    echo "FAIL: $1 (pattern unexpectedly matched: $2)"
    fail=1
  else
    echo "PASS: $1"
  fi
}

tfcheck  "textfile label with spaces"   'tf_labelled\{sensor=Temp Salón\}=26\.53'
tfcheck  "textfile bare metric"         'tf_plain\{\}=42'
tfcheck  "textfile trailing timestamp dropped" 'tf_timestamped\{sensor=x\}=7$'
tfcheck  "textfile brace inside label"  'tf_brace_in_label\{sensor=raro\}dentro\}=3\.5'
tfcheck  "textfile leading whitespace"  'tf_indented\{a=b\}=1'
tfcheck  "textfile mtime emitted"       'node_textfile_mtime_seconds\{file=unit\.prom\}='
tfcheck  "textfile scrape_error clear"  'node_textfile_scrape_error\{\}=0'
tfrefute "textfile HELP/TYPE skipped"   'tf_labelled\{\}=|HELP'
tfrefute "textfile unterminated label skipped" 'tf_unterminated'
tfrefute "textfile valueless line skipped"     'tf_novalue'
tfrefute "textfile non-.prom ignored"          'tf_must_not_be_read'

# An unreadable directory must surface as scrape_error, not as silence.
TFMISS="$(TEXTFILE_DIR="$DIR/tests/.textfile-absent" "$BIN" --path.rootfs="$ROOT" \
          --dump=node_textfile 2>/dev/null)"
if printf '%s\n' "$TFMISS" | grep -qE 'node_textfile_scrape_error\{\}=1'; then
  echo "PASS: missing textfile dir reported as scrape_error"
else
  echo "FAIL: missing textfile dir not reported (got: $TFMISS)"
  fail=1
fi

# Unset TEXTFILE_DIR must cost nothing at all, not even the error series.
TFOFF="$("$BIN" --path.rootfs="$ROOT" --dump=node_textfile 2>/dev/null)"
if [ -z "$TFOFF" ]; then
  echo "PASS: textfile collector inert when unconfigured"
else
  echo "FAIL: textfile collector emitted while unconfigured (got: $TFOFF)"
  fail=1
fi
rm -rf "$TFDIR"


# A hit sample cap must be reported, not swallowed. build/tests/pico_exporter-capped
# is the same code built with COLLECT_MAX_SAMPLES=120, since the real 8192 is out
# of reach on a test host.
CAPBIN="$DIR/build/tests/pico_exporter-capped"
if [ -x "$CAPBIN" ]; then
  CAPOUT="$("$CAPBIN" --dump= 2>"$DIR/tests/.capped.log")"
  CAPN="$(printf '%s' "$CAPOUT" | grep -c .)"
  CAPMETRIC="$(printf '%s' "$CAPOUT" |
               grep -c 'node_exporter_dropped_samples_total')"
  CAPWARN="$(grep -c 'sample caps hit' "$DIR/tests/.capped.log")"
  # 120 slots: 118 collector samples + the self-report, and `up` is only added
  # by the push loop, so --dump= yields 119 lines.
  if [ "$CAPN" = "119" ] && [ "$CAPMETRIC" = "1" ] && [ "$CAPWARN" = "1" ]; then
    echo "PASS: hit sample cap reported (119 samples, self-report metric, one stderr line)"
  else
    echo "FAIL: sample cap not reported (lines=$CAPN want 119, metric=$CAPMETRIC want 1, warn=$CAPWARN want 1)"
    fail=1
  fi
  rm -f "$DIR/tests/.capped.log"
else
  echo "SKIP: build/tests/pico_exporter-capped missing (run make test)"
fi

# --- hwmon/thermal ---
check "hwmon temp"                'node_hwmon_temp_celsius\{chip="cpu_thermal",label="cpu_thermal"\} 9\.15'
check "thermal zone"              'node_thermal_zone_temp\{zone="thermal_zone0"\} 9\.15'

# --- filesystem ---
check "fs root ext4"              'node_filesystem_size_bytes\{device="/dev/root",mountpoint="/",fstype="ext4"\}'
check "fs boot vfat"              'node_filesystem_size_bytes\{device="/dev/mmcblk0p1",mountpoint="/boot",fstype="vfat"\}'
refute "tmpfs excluded"           'fstype="tmpfs"'
refute "devtmpfs excluded"        'fstype="devtmpfs"'
refute "sysfs excluded"           'fstype="sysfs"'
refute "proc excluded"            'fstype="proc"'

# --- diskstats ---
check "disk reads mmcblk0"        'node_disk_reads_completed_total\{device="mmcblk0",disk="mmcblk0"\} 273'
check "disk read bytes p1"        'node_disk_read_bytes_total\{device="mmcblk0p1"\} 9094656'
check "disk writes mmcblk0"       'node_disk_writes_completed_total\{device="mmcblk0",disk="mmcblk0"\} 17454'

# --- network ---
check "net rx eth0"               'node_network_receive_bytes_total\{device="eth0"\} 1000'
check "net tx eth0"               'node_network_transmit_bytes_total\{device="eth0"\} 2000'
check "net rx packets eth0"       'node_network_receive_packets_total\{device="eth0"\} 100'
refute "loopback excluded"        'device="lo"'

# --- pressure absent ---
refute "pressure absent (no /proc/pressure)" 'node_pressure_'

# --- systemd counts (no per-unit detail) ---
# SYSTEMD is off in the default build, so these run against the dedicated
# systemd-enabled binary rather than $M.
refute "default build has no systemd collector" '^node_systemd_units\{'
SYSDBIN="$DIR/build/tests/pico_exporter-systemd"
if [ -x "$SYSDBIN" ]; then
  MS="$("$SYSDBIN" --path.rootfs="$ROOT" --metrics-once 2>/dev/null)"
  if printf '%s' "$MS" | grep -aqE '^node_systemd_unit_state'; then
    echo "FAIL: per-unit detail removed"
    fail=1
  else
    echo "PASS: per-unit detail removed"
  fi
  hostUnits="$(systemctl list-units --all --type=service --plain --no-legend --no-pager | wc -l)"
  countSeries="$(printf '%s' "$MS" | grep -a '^node_systemd_units{' | wc -l)"
  countSum="$(printf '%s' "$MS" | grep -a '^node_systemd_units{' | grep -aoE '[0-9]+$' | awk '{s+=$1} END{print s+0}')"
  stateLabel="$(printf '%s' "$MS" | grep -ac '^node_systemd_units{state="[a-z]*",type="service"}' )"
  echo "systemd: host-units=$hostUnits count-series=$countSeries sum=$countSum"
  if [ "$hostUnits" -gt 0 ] && [ "$countSum" -eq "$hostUnits" ]; then
    echo "PASS: systemd counts sum to host unit total"
  else
    echo "FAIL: systemd count sum (hostUnits=$hostUnits sum=$countSum)"
    fail=1
  fi
  if [ "$countSeries" -gt 0 ] && [ "$countSeries" -eq "$stateLabel" ]; then
    echo "PASS: every node_systemd_units series has a state label"
  else
    echo "FAIL: node_systemd_units series/state-label mismatch (series=$countSeries labeled=$stateLabel)"
    fail=1
  fi
  if grep -aqE '^node_systemd_units\{[^{]*,type="service"\} 0$' <<<"$MS"; then
    echo "FAIL: a node_systemd_units count of 0 was emitted"
    fail=1
  else
    echo "PASS: no zero systemd count series"
  fi
else
  echo "SKIP: build/tests/pico_exporter-systemd missing (run make test)"
fi

# --- /boot filesystem must exist (statvfs) ---
if grep -aqE 'mountpoint="/boot"' <<<"$M"; then
  echo "PASS: /boot filesystem present"
else
  echo "FAIL: /boot filesystem missing"
  fail=1
fi

# --- OTLP encode/decode round-trip (no golden fixtures) ---
# run_tests encode feeds the --metrics-once lines back through the encoder and
# checks its own output with an independent protobuf walker: every sample must
# round-trip its name, labels, value and timestamp, resource attrs must survive,
# and _total metrics must be encoded as Sum / everything else as Gauge.
ENCSAMP="$DIR/tests/.M.txt"
RTS="$RANDOM$RANDOM"
enc_ok() { # enc_ok <desc> <ts> <nres> <first> <count> <res...>
  local desc="$1"; shift
  if "$HARNESS" encode "$@" <"$ENCSAMP" >"$RTS.log" 2>&1; then
    case "$desc" in
      *full*)   echo "PASS: OTLP round-trip $desc ($(grep -ao '[0-9]* samples' "$RTS.log" | cut -d' ' -f1) samples)" ;;
      *)        echo "PASS: OTLP round-trip $desc" ;;
    esac
  else
    echo "FAIL: OTLP round-trip $desc"; cat "$RTS.log"; fail=1
  fi
}
if [ -x "$HARNESS" ]; then
  TS="1760000000000000000"
  RES=('job=pico' 'instance=testhost, v2' 'app=pico')
  enc_ok "full set"              "$TS" 3 0 0     "${RES[@]}"
  enc_ok "slice [10,15)"         "$TS" 3 10 5    "${RES[@]}"
  enc_ok "empty slice (past end)" "$TS" 3 99999 0 "${RES[@]}"
  rm -f "$RTS.log"
else
  echo "SKIP: OTLP round-trip (build/tests/run_tests missing)"
fi

# --- keep-alive: 3 POSTs over one connection ---
if command -v python3 >/dev/null 2>&1; then
  rm -f "$DIR/tests/.sink_keepalive.bin"
  python3 "$DIR/tests/sink.py" "$DIR/tests/.sink_keepalive.bin" 31401 &
  KA_SINKD=$!
  sleep 0.5
  KAOUT="$("$HARNESS" keepalive 2>&1)"
  kill "$KA_SINKD" 2>/dev/null
  wait "$KA_SINKD" 2>/dev/null
  KFRAMES="$(python3 "$DIR/tests/verify_batch.py" "$DIR/tests/.sink_keepalive.bin" 2>/dev/null | grep -ao 'frames=[0-9]*' | cut -d= -f2)"
  if [ "$KFRAMES" -eq 3 ] && echo "$KAOUT" | grep -q 'alive=1'; then
    echo "PASS: keep-alive 3 POSTs on one connection"
  else
    echo "FAIL: keep-alive (frames=$KFRAMES)"; echo "$KAOUT"; fail=1
  fi
else
  echo "SKIP: keep-alive (python3 not found)"
fi

# --- TLS validation against the real endpoint (needs network) ---
TLSOUT="$("$HARNESS" tls 2>&1)"
if echo "$TLSOUT" | grep -q 'tls_handshake: SKIP'; then
  echo "SKIP: TLS validation (no network)"
elif echo "$TLSOUT" | grep -q 'tls_handshake: OK'; then
  echo "PASS: TLS validation (valid chain, 405, stale clock rejected)"
else
  echo "FAIL: TLS validation"; echo "$TLSOUT"; fail=1
fi

# --- wrong trust anchor must be rejected (62) ---
WTOUT="$("$HARNESS" tls-bad 2>&1)"
if echo "$WTOUT" | grep -q 'tls_handshake: SKIP'; then
  echo "SKIP: wrong trust anchor (no network)"
elif echo "$WTOUT" | grep -q 'tls_handshake: OK'; then
  echo "PASS: wrong trust anchor rejected (62)"
else
  echo "FAIL: wrong trust anchor not rejected"; echo "$WTOUT"; fail=1
fi

# --- TLS session-id probe against the real gateway (needs network) ---
RSOUT="$("$HARNESS" resume 2>&1)"
if echo "$RSOUT" | grep -q 'SKIP'; then
  echo "SKIP: TLS session-id probe (no network)"
elif echo "$RSOUT" | grep -q 'tls_resume: NO SESSION ID'; then
  echo "SKIP: TLS session resumption (gateway issues no session id; see AGENTS.md)"
elif echo "$RSOUT" | grep -q 'tls_resume: SESSION ID ISSUED'; then
  echo "NOTE: gateway now issues TLS session ids -- revisit resumption (see AGENTS.md)"
else
  echo "FAIL: TLS session-id probe"; echo "$RSOUT"; fail=1
fi

# --- oversized-record recovery (bg_test_force_too_large seam in the harness) ---
if [ -x "$HARNESS" ]; then
  FBOUT="$("$HARNESS" fallback 2>&1)"
  case "$FBOUT" in
    *"tls_fallback: OK"*) echo "PASS: oversized-record recovery (${FBOUT#tls_fallback: OK })" ;;
    *)                    echo "FAIL: oversized-record recovery: $FBOUT"; fail=1 ;;
  esac
else
  echo "SKIP: build/tests/run_tests missing (run make test)"
fi

# --- push to a local plain-HTTP sink ---
if command -v python3 >/dev/null 2>&1; then
  SINKPORT=$((30000 + RANDOM % 10000))
  rm -f "$DIR/tests/.sink.bin"
  python3 "$DIR/tests/sink.py" "$DIR/tests/.sink.bin" "$SINKPORT" &
  SINKD=$!
  sleep 0.5
  GW_URL="http://127.0.0.1:$SINKPORT/rw" GW_USER="" GW_PASS="" \
  INSTANCE="testhost" INTERVAL=2 \
  "$BIN" --path.rootfs="$ROOT" \
    >"$DIR/tests/.push.log" 2>&1 &
  PUSHD=$!
  # --- resting footprint, sampled while the process sleeps between cycles.
  # smaps_rollup walks the page tables and is exact; VmRSS in status is a
  # batched per-CPU counter and can lag by up to 128 kB (see AGENTS.md).
  # Three samples 0.3 s apart, minimum wins, so a sample that lands inside
  # the ~10 ms cycle cannot fail the gate on its own.
  sleep 1.5
  MINFLT0="$(awk '{print $10}' /proc/$PUSHD/stat 2>/dev/null || echo 0)"
  sleep 2.5
  # 999999 is the "no sample" sentinel; the loop's own fallback shares it,
  # so a read that fails can never look like the smallest RSS seen.
  RSS_MIN=999999
  for _ in 1 2 3; do
    r="$(awk '/^Rss:/{print $2}' /proc/$PUSHD/smaps_rollup 2>/dev/null || echo 999999)"
    r="${r:-999999}"
    [ "$r" -lt "$RSS_MIN" ] && RSS_MIN="$r"
    sleep 0.3
  done
  HEAPS="$(grep -c '\[heap\]' /proc/$PUSHD/maps 2>/dev/null)"
  HEAPS="${HEAPS:-0}"
  sleep 1
  MINFLT1="$(awk '{print $10}' /proc/$PUSHD/stat 2>/dev/null || echo 0)"
  ALIVE=0
  kill -0 "$PUSHD" 2>/dev/null && ALIVE=1
  kill "$PUSHD" "$SINKD" 2>/dev/null
  wait "$PUSHD" 2>/dev/null
  if [ -s "$DIR/tests/.sink.bin" ] \
     && grep -aq "pushed=true http=200" "$DIR/tests/.push.log"; then
    echo "PASS: push to local sink (received $(stat -c %s "$DIR/tests/.sink.bin" 2>/dev/null || echo 0) bytes)"
  else
    echo "FAIL: push to local sink"
    cat "$DIR/tests/.push.log"
    fail=1
  fi
  if [ "$ALIVE" -eq 1 ]; then
    if [ "$RSS_MIN" -le 32 ]; then
      echo "PASS: resting RSS ${RSS_MIN} kB (<= 32 kB, smaps_rollup)"
    else
      echo "FAIL: resting RSS ${RSS_MIN} kB (want <= 32 kB)"
      fail=1
    fi
    if [ "${HEAPS:-0}" -eq 0 ]; then
      echo "PASS: no [heap] mapping"
    else
      echo "FAIL: [heap] mapping present (picolibc malloc was called)"
      fail=1
    fi
    # Two INTERVAL=2 cycles fit in the ~4.4 s window; 16 per cycle measured
    # against the fake rootfs; a real /proc costs more arena pages, hence the
    # headroom. 320 catches an idle path that drops something live and
    # thrashes on it.
    FAULTS=$((MINFLT1 - MINFLT0))
    if [ "$FAULTS" -ge 0 ] && [ "$FAULTS" -le 320 ]; then
      echo "PASS: minor faults over two cycles = $FAULTS (<= 320)"
    else
      echo "FAIL: minor faults over two cycles = $FAULTS (want 0..320)"
      fail=1
    fi
  else
    echo "FAIL: exporter exited during the idle window (footprint gates not evaluated)"
    fail=1
  fi

  # --- batched push (BATCH=100): several frames, all decode ---
  BPORT=$((30000 + RANDOM % 10000))
  rm -f "$DIR/tests/.sink_batch.bin" "$DIR/tests/.sink_batch.bin.conns"
  python3 "$DIR/tests/sink.py" "$DIR/tests/.sink_batch.bin" "$BPORT" &
  BP_SINKD=$!
  sleep 0.5
  GW_URL="http://127.0.0.1:$BPORT/rw" GW_USER="" GW_PASS="" \
  INSTANCE="testhost" INTERVAL=2 BATCH=100 \
  timeout 7 "$BIN" --path.rootfs="$ROOT" \
    >"$DIR/tests/.push_batch.log" 2>&1
  kill "$BP_SINKD" 2>/dev/null
  wait "$BP_SINKD" 2>/dev/null
  BLKS="$(grep -ao 'blks=[0-9]*' "$DIR/tests/.push_batch.log" | head -1)"
  VB="$(python3 "$DIR/tests/verify_batch.py" "$DIR/tests/.sink_batch.bin" 2>/dev/null || true)"
  if [ -n "$VB" ] \
     && [ "$(echo "$VB" | grep -ao 'frames=[0-9]*' | cut -d= -f2)" -ge 4 ] \
     && [ "$(echo "$VB" | grep -ao 'series=[0-9]*' | cut -d= -f2)" -ge 250 ]; then
    echo "PASS: batched push (${BLKS:-blks=0} per cycle, sink decoded: $VB)"
  else
    echo "FAIL: batched push (log: $BLKS, sink: ${VB:-none})"
    cat "$DIR/tests/.push_batch.log"
    fail=1
  fi

  # --- the connection survives the sleep, not just the batches of one cycle.
  # Several cycles of several batches each must all ride one TCP connection;
  # a regression here costs a full TLS handshake per cycle (24.5 ms of CPU on
  # the Pi) without failing any other assertion.
  CYCLES="$(grep -c '^cycle ' "$DIR/tests/.push_batch.log" || true)"
  CONNS="$(wc -l < "$DIR/tests/.sink_batch.bin.conns" 2>/dev/null || echo 0)"
  if [ "${CYCLES:-0}" -ge 2 ] && [ "${CONNS:-0}" -eq 1 ]; then
    echo "PASS: one connection across $CYCLES cycles (keep-alive spans the sleep)"
  else
    echo "FAIL: keep-alive across cycles (cycles=$CYCLES tcp_connections=$CONNS, want 1)"
    fail=1
  fi
  if grep -q 'reopen=' "$DIR/tests/.push_batch.log"; then
    echo "FAIL: reopen= reported against a sink that never drops the connection"
    grep -o 'reopen=[0-9]*' "$DIR/tests/.push_batch.log" | head -3
    fail=1
  fi

  # --- sample round-trip: every dumped sample must arrive on the wire ---
  rm -f "$DIR/tests/.sink_onetime.bin"
  python3 "$DIR/tests/sink.py" "$DIR/tests/.sink_onetime.bin" "$BPORT" &
  BP_SINKD=$!
  sleep 0.5
  DUMP_COUNT="$("$BIN" --dump= 2>/dev/null | wc -l)"
  GW_URL="http://127.0.0.1:$BPORT/rw" GW_USER="" GW_PASS="" \
  INSTANCE="testhost" INTERVAL=60 \
  timeout 4 "$BIN" >"$DIR/tests/.push_onetime.log" 2>&1
  kill "$BP_SINKD" 2>/dev/null
  wait "$BP_SINKD" 2>/dev/null
  ONETIME="$(python3 "$DIR/tests/verify_batch.py" "$DIR/tests/.sink_onetime.bin" 2>/dev/null || true)"
  if [ -n "$ONETIME" ] && [ "$(echo "$ONETIME" | grep -ao 'series=[0-9]*' | cut -d= -f2)" -eq "$((DUMP_COUNT + 1))" ]; then
    echo "PASS: one-cycle pushed series ($ONETIME) == dumped samples + up ($((DUMP_COUNT + 1)))"
  else
    echo "FAIL: pushed series != dumped + up (dump=$DUMP_COUNT, sink: ${ONETIME:-none})"
    cat "$DIR/tests/.push_onetime.log"
    fail=1
  fi
else
  echo "SKIP: push/batch tests (python3 not found)"
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "ALL TESTS PASSED"
else
  echo "SOME TESTS FAILED"
fi
exit "$fail"