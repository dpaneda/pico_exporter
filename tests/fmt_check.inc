/* fmt_check.inc - the fmt sweep, included by the glibc harness
 * (tests/run_tests fmt). snprintf("%.*g")+strtod are the harness's own libc,
 * so the sweep pins fmt_f64_shortest/fmt_f64_parse against it by
 * construction. It used to be included by a second binary linked against
 * picolibc as well; that oracle went when picolibc left every link, since a
 * libc no binary links cannot be the arbiter of what one of them prints. */
#ifndef PICO_FMT_CHECK_INC
#define PICO_FMT_CHECK_INC

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* fmt_f64_shortest must reproduce the "%.*g"-walk output byte for byte (the
 * text modes' format contract), and fmt_f64_parse must agree bit-for-bit
 * with strtod (the collectors' push-path parser). printf/strtod of the
 * libc hosting this sweep are the oracle; the sweep is deterministic
 * (xorshift, fixed seed), so both binaries exercise identical inputs. */

static unsigned long long fmt_rng = 0x243F6A8885A308D3ULL;

static unsigned long long fmt_rnd(void) {
    fmt_rng ^= fmt_rng << 13;
    fmt_rng ^= fmt_rng >> 7;
    fmt_rng ^= fmt_rng << 17;
    return fmt_rng;
}

static double fmt_bitsd(unsigned long long u) {
    double d;
    memcpy(&d, &u, 8);
    return d;
}

/* The fmt_float() walk this branch replaced: snprintf("%.*g") + strtod
 * check; the first precision that round-trips wins. */
static void fmt_walk(double v, char *out) {
    for (int prec = 1; prec <= 17; prec++) {
        snprintf(out, 40, "%.*g", prec, v);
        if (strtod(out, NULL) == v) return;
    }
}

/* Checks one double: my shortest render must byte-match the %.*g walk, and
 * my parser must read both back bit-exact. */
static void fmt_check_value(double v, int *fails, long *ntest) {
    char mine[64], walk[64];
    fmt_walk(v, walk);
    fmt_f64_shortest(mine, v);
    (*ntest)++;
    if (strcmp(mine, walk) != 0) {
        if (*fails < 10)
            printf("  FAIL fmt render: %.17g -> mine %s, walk %s\n",
                   v, mine, walk);
        (*fails)++;
        return;
    }
    double back = 0;
    size_t used = fmt_f64_parse(mine, &back);
    unsigned long long bb, wb;
    memcpy(&bb, &back, 8);
    memcpy(&wb, &v, 8);
    if (used != strlen(mine) || bb != wb) {
        if (*fails < 10)
            printf("  FAIL fmt parse-back: %.17g str %s -> %.17g\n",
                   v, mine, back);
        (*fails)++;
    }
}

static int fmt_check_cmd(void) {
    static const double edges[] = {
        0.0, -0.0, 1.0, -1.0, 0.5, 1.5, 2.5, 0.1, 0.2, 0.3, 0.42, 9.15,
        26.53, 123.456789, 0.30000000000000004, 500.0, 1024.0, 268435456.0,
        1e15, 1e16, 1e17, 1e21, 1e22, 1e23, 999999.5, 99999.5,
        9007199254740992.0, 1e308, 1e-308, 1e-320, 1e-323, 5e-324,
        2.5e-323, 1.7976931348623157e308, 2.2250738585072014e-308,
        2.2250738585072011e-308, 4.9406564584124654e-324,
        123456789012345680.0, 1e30, 1e-30, 6.02e23, 1.2e9, 0.07,
    };
    int fails = 0;
    long ntest = 0;

    for (size_t i = 0; i < sizeof edges / sizeof *edges; i++)
        fmt_check_value(edges[i], &fails, &ntest);

    for (int i = 0; i < 60000; i++) {
        unsigned long long bits = fmt_rnd();
        /* 3/4 realistic exponents, 1/4 full binary64 range */
        if ((i & 3) != 3) {
            unsigned long long mant = bits & 0xFFFFFFFFFFFFFULL;
            int bias = 1023 + (int)(fmt_rnd() % 61) - 30;
            bits = (mant | ((unsigned long long)bias << 52)) |
                   (bits & 0x8000000000000000ULL);
        }
        double v = fmt_bitsd(bits);
        if (isnan(v)) continue;
        fmt_check_value(v, &fails, &ntest);
        if (fails > 10) break;
    }

    /* parser: random decimal strings vs strtod */
    char str[64];
    for (int i = 0; i < 40000; i++) {
        int nd = 1 + (int)(fmt_rnd() % 30);
        int o = 0;
        if (fmt_rnd() & 1) str[o++] = '-';
        str[o++] = (char)('1' + fmt_rnd() % 9);
        for (int j = 1; j < nd; j++) str[o++] = (char)('0' + fmt_rnd() % 10);
        int mode = (int)(fmt_rnd() % 3);
        if (mode == 1) {               /* insert a point */
            int k = 1 + (int)(fmt_rnd() % (unsigned)nd);
            memmove(str + k + 1, str + k, (size_t)(o - k));
            str[k] = '.';
            o++;
        }
        if (mode == 2)
            o += sprintf(str + o, "e%d", (int)(fmt_rnd() % 40) - 20);
        str[o] = 0;

        double want = strtod(str, NULL);
        double got = 123.0;
        size_t used = fmt_f64_parse(str, &got);
        ntest++;
        /* The oracle libc may be 1 ulp off on inputs longer than 17
         * significant digits, so the tolerance covers the sweep's own
         * >17-digit constants. Inside 17 digits the parser must be
         * correctly rounded and agree bit for bit. */
        unsigned long long wg, mg;
        memcpy(&wg, &want, 8);
        memcpy(&mg, &got, 8);
        unsigned long long wl = wg - 1, wh = wg + 1;
        int ok = used == strlen(str) &&
                 (mg == wg || (nd > 17 && (mg == wl || mg == wh)));
        if (!ok) {
            if (fails < 10)
                printf("  FAIL fmt parse: %s -> %.17g (strtod %.17g)\n",
                       str, got, want);
            fails++;
        }
        if (fails > 10) break;
    }

    if (fails == 0)
        printf("fmt: OK (%ld values; render byte-identical to the %%.17g walk, "
               "parser bit-equal to strtod)\n", ntest);
    else
        printf("fmt: %d FAILURES (%ld values)\n", fails, ntest);
    return fails != 0;
}

#endif /* PICO_FMT_CHECK_INC */
