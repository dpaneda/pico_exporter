#!/usr/bin/env python3
"""Decode the sink.py frame log and count datapoints/metrics per frame."""
import struct, sys

def parse_varint(buf, pos):
    shift, val = 0, 0
    while pos < len(buf):
        b = buf[pos]; pos += 1
        val |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
    return val, pos

def parse_fields(buf):
    fields, pos, failsafe = [], 0, 0
    while pos < len(buf) and failsafe < 1_000_000:
        failsafe += 1
        tag, pos = parse_varint(buf, pos)
        field, wire = (tag >> 3), (tag & 7)
        if wire == 0:
            _, pos = parse_varint(buf, pos)
        elif wire == 1:
            pos += 8
        elif wire == 2:
            n, pos = parse_varint(buf, pos)
            fields.append((field, buf[pos:pos + n])); pos += n
        elif wire == 5:
            pos += 4
        else:
            break
    return fields

def dp_count(body):
    count = 0
    for f1, rm in parse_fields(body):
        if f1 != 1: continue
        for f2, sm in parse_fields(rm):
            if f2 != 2: continue
            for f3, met in parse_fields(sm):
                if f3 != 2: continue
                for f4, gauge_or_sum in parse_fields(met):
                    if f4 not in (5, 7): continue
                    for f5, dp in parse_fields(gauge_or_sum):
                        if f5 == 1: count += 1
    return count

data = open(sys.argv[1], "rb").read()
frames, points, pos = 0, 0, 0
while pos + 4 <= len(data):
    n = struct.unpack(">I", data[pos:pos + 4])[0]; pos += 4
    if pos + n > len(data):
        sys.exit("verify_batch: truncated frame %d" % frames)
    points += dp_count(data[pos:pos + n]); pos += n; frames += 1
print("frames=%d series=%d" % (frames, points))
