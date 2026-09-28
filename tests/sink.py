#!/usr/bin/env python3
# sink.py - minimal HTTP sink that records the raw remote-write payload.
# SINK_DELAY_MS adds a per-request delay, so a test can make the push take a
# known time: a fast peer hides the period-vs-delay bug entirely.
import http.server
import os
import sys
import time

DELAY = int(os.environ.get("SINK_DELAY_MS", "0")) / 1000.0


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        # Once per accepted TCP connection, so <file>.conns tells the
        # keep-alive tests how many the client actually opened.
        super().setup()
        with open(sys.argv[1] + ".conns", "a") as f:
            f.write("1\n")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n)
        with open(sys.argv[1], "ab") as f:
            f.write(len(body).to_bytes(4, "big"))
            f.write(body)
        if DELAY:
            time.sleep(DELAY)
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_):
        pass


http.server.HTTPServer(("0.0.0.0", int(sys.argv[2])), Handler).serve_forever()
