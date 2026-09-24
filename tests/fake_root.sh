#!/usr/bin/env bash
# Generate a synthetic fake rootfs so the exporter can be tested without a host.
# Usage: fake_root.sh <target-dir>
set -euo pipefail
ROOT="${1:?usage: fake_root.sh <target-dir>}"
rm -rf "$ROOT"
mkdir -p "$ROOT"/boot \
         "$ROOT"/proc/sys/kernel/random "$ROOT"/proc/sys/fs "$ROOT"/proc/net \
         "$ROOT"/sys/class/net/eth0/statistics "$ROOT"/sys/class/net/lo/statistics \
         "$ROOT"/sys/class/net/wlan0/statistics \
         "$ROOT"/sys/devices/system/cpu/cpu{0,1,2,3}/cpufreq \
         "$ROOT"/sys/class/hwmon/hwmon0 "$ROOT"/sys/class/hwmon/hwmon1 \
         "$ROOT"/sys/class/thermal/thermal_zone0 \
         "$ROOT"/sys/block/mmcblk0/mmcblk0p1 "$ROOT"/sys/block/mmcblk0/mmcblk0p2 \
         "$ROOT"/sys/block/sda/sda1 "$ROOT"/sys/block/sda/sda2

mk() { printf '%b' "$2" > "$ROOT/$1"; }

mk proc/meminfo \
"MemTotal:        1000000 kB
MemFree:          200000 kB
MemAvailable:     500000 kB
Buffers:            5000 kB
Cached:           300000 kB
SwapCached:            0 kB
Active:           100000 kB
Inactive:         150000 kB
Active(anon):      40000 kB
Inactive(anon):    10000 kB
Dirty:               100 kB
Shmem:             20000 kB
SReclaimable:      40000 kB
CommitLimit:      500000 kB
Committed_AS:     350000 kB
SwapTotal:        100000 kB
SwapFree:          95000 kB
Writeback:            10 kB
"

mk proc/vmstat \
"nr_free_pages 52394
nr_zone_inactive_anon 255
nr_zone_active_anon 5244
pgpgin 1234567
pgpgout 9876543
pgfault 6156412
pgmajfault 89012
pswpin 123
pswpout 456
"

mk proc/diskstats "0 0 ram0 0 0 0 0 0 0 0 0 0 0 0 0 0
0 0 loop0 0 0 0 0 0 0 0 0 0 0 0 0 0
0 0 mmcblk0 273 14 17763 27 17454 12 3589 26 1 1 1 4238 0
0 0 mmcblk0p1 273 14 17763 27 1 0 7 1 7 2 0 1 2 0
0 0 mmcblk0p2 50 4 3000 3 17453 12 3582 25 67 4262 5 4 4236 0
0 0 sda 100 3 5000 10 200 5 4000 20 30 100 4 3 80 0 7 1
0 0 sda1 100 3 5000 10 0 0 0 0 0 0 0 0 0 0 7 1
0 0 sda2 0 0 0 0 200 5 4000 20 30 100 4 3 80 0 0 0
"

mk proc/loadavg "0.42 0.51 0.58 1/100 1234
"

mk proc/stat \
"cpu  1000 10 2000 50000 300 40 50 0 0 0
cpu0 100 1 200 5000 30 4 5 0 0 0
cpu1 100 1 200 5000 30 4 5 0 0 0
cpu2 100 1 200 5000 30 4 5 0 0 0
cpu3 100 1 200 5000 30 4 5 0 0 0
intr 12345678 0 0 0 0 0 0 0 0 0 0 0
ctxt 1234567
btime 1788600000
processes 77881
procs_running 2
procs_blocked 0
softirq 1000 1 2 3 4 5 6 7 8 9
"

mk proc/sys/fs/file-nr "1024    0    4096
"
mk proc/sys/kernel/random/entropy_avail "512
"
mk proc/sys/kernel/random/poolsize "4096
"

mk proc/net/snmp "Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates
Ip: 1 64 12345 0 0 0 0 0 12345 12000 0 0 0 0 0 0 0 0 0
Icmp: InMsgs InErrors InCsumErrors InDestUnreachs
Icmp: 10 0 0 1
Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors
Tcp: 1 200 120000 -1 100 90 2 1 8 54321 54321 5 0 1 0
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti
Udp: 9000 3 0 9001 0 0 0 0
"

mk proc/net/sockstat "sockets: used 10
TCP: inuse 6 orphan 0 tw 8 alloc 7 mem 12
UDP: inuse 1 mem 2
UDPLITE: inuse 0
RAW: inuse 0
FRAG: inuse 0 memory 0
"

mk proc/net/udp "sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
 1: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 12345 2 0000000000000000 0
 2: 00000000:0044 00000000:0000 07 00000010:00000020 00:00000000 00000000     0        0 12346 2 0000000000000000 0
"

mk proc/net/udp6 "sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
 1: 00000000000000000000000000000000:0035 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 12347 2 00000000000000000000000000000000 0
"

mk proc/mounts "/dev/root / ext4 rw,relatime 0 0
/dev/mmcblk0p1 /boot vfat rw,relatime,fmask=0022,dmask=0022 0 0
tmpfs /run tmpfs rw,nosuid,nodev 0 0
devtmpfs /dev devtmpfs rw,nosuid,size=10m 0 0
sysfs /sys sysfs rw,nosuid,nodev,noexec 0 0
proc /proc proc rw,nosuid,nodev,noexec 0 0
"

for dev in eth0 lo wlan0; do
  mk "sys/class/net/$dev/statistics/rx_bytes" "1000
"
  mk "sys/class/net/$dev/statistics/tx_bytes" "2000
"
  mk "sys/class/net/$dev/statistics/rx_packets" "100
"
  mk "sys/class/net/$dev/statistics/tx_packets" "200
"
done

for cpu in 0 1 2 3; do
  mk "sys/devices/system/cpu/cpu$cpu/cpufreq/scaling_cur_freq" "1200000
"
  mk "sys/devices/system/cpu/cpu$cpu/cpufreq/cpuinfo_max_freq" "1200000
"
  mk "sys/devices/system/cpu/cpu$cpu/cpufreq/cpuinfo_min_freq" "600000
"
  mk "sys/devices/system/cpu/cpu$cpu/cpufreq/scaling_governor" "ondemand
"
done

mk sys/class/hwmon/hwmon0/name "cpu_thermal
"
mk sys/class/hwmon/hwmon0/temp1_input "9150
"
mk sys/class/hwmon/hwmon0/temp1_crit "110000
"
mk sys/class/hwmon/hwmon1/name "rpi_volt
"
mk sys/class/thermal/thermal_zone0/temp "9150
"

mk sys/block/mmcblk0/mmcblk0p1/partition "1
"
mk sys/block/mmcblk0/mmcblk0p2/partition "2
"
mk sys/block/sda/sda1/partition "1
"
mk sys/block/sda/sda2/partition "2
"

echo "fake rootfs ready at $ROOT"