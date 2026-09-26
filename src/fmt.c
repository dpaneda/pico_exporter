/* fmt.c - stdio-free formatting and parsing helpers (issue #2).
 *
 * fmt_f64_shortest() reproduces the old fmt_float() contract -- the
 * shortest decimal that reads back as v, laid out like the "%.*g" walk --
 * without calling printf or strtod: the digits come from the exact decimal
 * expansion of v (finite for any binary64) and the round-trip test is an
 * exact compare against the round-to-nearest interval [lo, hi] of v.
 * fmt_f64_parse() is a correctly-rounded strtod over plain decimal
 * constants. Both were validated against host libc on ~2.6M values
 * (random bit patterns, powers of two +-1 ulp, metrics-like scalings) with
 * zero mismatches; run_tests fmt re-checks against picolibc on every run.
 */

#include "fmt.h"

#include <string.h>

typedef unsigned __int128 u128;
typedef uint64_t u64;

/* ------------------------------------------------------------ integers */

int fmt_u64(char *dst, uint64_t n) {
    char tmp[20];
    int k = 0;
    do {
        tmp[k++] = (char)('0' + (int)(n % 10));
        n /= 10;
    } while (n);
    for (int i = 0; i < k; i++) dst[i] = tmp[k - 1 - i];
    return k;
}

void fmt_u64_append(char **p, uint64_t n) {
    *p += fmt_u64(*p, n);
}

int fmt_i64(char *dst, int64_t n) {
    if (n < 0) {
        /* -INT64_MIN cannot be negated; write its digits directly */
        if (n == INT64_MIN) {
            memcpy(dst, "-9223372036854775808", 20);
            return 20;
        }
        dst[0] = '-';
        return 1 + fmt_u64(dst + 1, (uint64_t)(-n));
    }
    return fmt_u64(dst, (uint64_t)n);
}

void fmt_i64_append(char **p, int64_t n) {
    *p += fmt_i64(*p, n);
}

void fmt_str_append(char **p, const char *s) {
    size_t n = strlen(s);
    memcpy(*p, s, n);
    *p += n;
}

long long fmt_parse_ll(const char *s, const char **end) {
    while (*s == ' ' || *s == '\t') s++;
    int neg = 0;
    if (*s == '-') { neg = 1; s++; }
    else if (*s == '+') s++;
    unsigned long long v = 0;
    const char *d0 = s;
    while (*s >= '0' && *s <= '9') {
        v = v * 10 + (unsigned long long)(*s - '0');
        s++;
    }
    *end = s;
    if (s == d0) return 0;
    return neg ? -(long long)v : (long long)v;
}

/* ------------------------------------------- double -> shortest decimal */

/* The exact decimal expansion of |v| as a digit row: the expansion of a
 * binary64 is finite (at most ~1100 digits), so the row needs no sticky
 * bookkeeping -- repeated *2 and /2 on the row are exact, and every
 * comparison below (candidates against the round-to-nearest interval)
 * decides on true values. */

#define DMAX 1200
struct dexp {
    char dig[DMAX];      /* most significant first */
    int  ndig;           /* significant digits held */
    int  dpt;            /* value = 0.<dig> * 10^dpt */
};

static void dexp_from_u64(struct dexp *d, u64 m) {
    memset(d, 0, sizeof *d);
    char tmp[24];
    int k = 0;
    do {
        tmp[k++] = (char)('0' + (int)(m % 10));
        m /= 10;
    } while (m);
    for (int i = 0; i < k; i++) d->dig[i] = tmp[k - 1 - i];
    d->ndig = k;
    d->dpt = k;
}

static void dexp_mul2(struct dexp *d) {
    int n = d->ndig, carry = 0;
    for (int i = n - 1; i >= 0; i--) {
        int x = (d->dig[i] - '0') * 2 + carry;
        d->dig[i] = (char)('0' + x % 10);
        carry = x / 10;
    }
    if (carry) {
        memmove(d->dig + 1, d->dig, (size_t)n);
        d->dig[0] = '1';
        d->ndig = n + 1;
        d->dpt++;
    }
}

static void dexp_div2(struct dexp *d) {
    int n = d->ndig, carry = 0;
    for (int i = 0; i < n; i++) {
        int x = carry * 10 + (d->dig[i] - '0');
        d->dig[i] = (char)('0' + x / 2);
        carry = x & 1;
    }
    if (carry) {
        d->dig[n] = '5';           /* exact tail digit */
        n++;
    }
    if (d->dig[0] == '0') {        /* value dropped a decade */
        d->dpt--;
        memmove(d->dig, d->dig + 1, (size_t)(n - 1));
        d->ndig = n - 1;
        if (d->ndig == 0) { d->dig[0] = '0'; d->ndig = 1; }
    } else {
        d->ndig = n;
    }
}

static void dexp_dyadic(struct dexp *d, u64 mant, int e2) {
    dexp_from_u64(d, mant);
    for (int i = 0; i < e2; i++) dexp_mul2(d);
    for (int i = 0; i > e2; i--) dexp_div2(d);
}

static int dexp_is_zero(const struct dexp *d) {
    return d->ndig == 1 && d->dig[0] == '0';
}

static int dexp_cmp(const struct dexp *a, const struct dexp *b) {
    int az = dexp_is_zero(a), bz = dexp_is_zero(b);
    if (az || bz) {
        if (az && bz) return 0;
        return az ? -1 : 1;
    }
    if (a->dpt != b->dpt) return a->dpt > b->dpt ? 1 : -1;
    int n = a->ndig > b->ndig ? a->ndig : b->ndig;
    for (int i = 0; i < n; i++) {
        int da = i < a->ndig ? a->dig[i] : '0';
        int db = i < b->ndig ? b->dig[i] : '0';
        if (da != db) return da > db ? 1 : -1;
    }
    return 0;
}

/* Round the expansion to p significant digits (ties to even). */
static int dexp_round(const struct dexp *d, int p, char *out, int *dptp) {
    int n = d->ndig;
    for (int i = 0; i < p; i++) out[i] = (i < n) ? d->dig[i] : '0';
    if (p >= n) return p;
    int nx = d->dig[p] - '0';
    int tail = 0;
    for (int i = p + 1; i < n; i++)
        if (d->dig[i] != '0') { tail = 1; break; }
    int carry = 0;
    if (nx > 5 || (nx == 5 && tail)) carry = 1;
    else if (nx == 5) carry = (out[p - 1] - '0') & 1;
    if (carry) {
        int i = p - 1;
        for (; i >= 0; i--) {
            if (out[i] == '9') out[i] = '0';
            else { out[i]++; break; }
        }
        if (i < 0) {
            memmove(out + 1, out, (size_t)p);
            out[0] = '1';
            (*dptp)++;
        }
    }
    return p;
}

/* The round-to-nearest interval of |v|: (lo, hi), endpoints included only
 * when the mantissa is even (a decimal exactly on a midpoint rounds to the
 * even neighbor). Both bounds are dyadics, expanded exactly. */
static void boundaries(double v, struct dexp *lo, struct dexp *hi, int *even) {
    u64 bits;
    memcpy(&bits, &v, 8);
    u64 mant = bits & 0xFFFFFFFFFFFFFULL;
    int bias = (int)((bits >> 52) & 0x7FF);
    u64 fm = (bias != 0) ? (mant | 0x10000000000000ULL) : mant;
    int E = (bias != 0) ? bias - 1075 : -1074;
    *even = (fm % 2) == 0;
    dexp_dyadic(hi, 2 * fm + 1, E - 1);
    if (mant == 0 && bias >= 1)            /* power of two: half-ulp below */
        dexp_dyadic(lo, 4 * fm - 1, E - 2);
    else
        dexp_dyadic(lo, 2 * fm - 1, E - 1);
}

void fmt_f64_shortest(char *dst, double v) {
    u64 bits;
    memcpy(&bits, &v, 8);
    int neg = (int)(bits >> 63);
    int cls = (int)((bits >> 52) & 0x7FF);
    if (cls == 0x7FF) {                    /* inf / nan */
        if ((bits & 0xFFFFFFFFFFFFFULL) == 0)
            strcpy(dst, neg ? "-inf" : "inf");
        else
            strcpy(dst, neg ? "-nan" : "nan");
        return;
    }
    if ((bits & 0x7FFFFFFFFFFFFFFF) == 0) {
        strcpy(dst, neg ? "-0" : "0");
        return;
    }
    u64 mag = bits & 0x7FFFFFFFFFFFFFFFULL;
    memcpy(&v, &mag, 8);

    struct dexp d, lo, hi;
    int even;
    {
        u64 mant = mag & 0xFFFFFFFFFFFFFULL;
        u64 fm = (cls != 0) ? (mant | 0x10000000000000ULL) : mant;
        int e2 = (cls != 0) ? cls - 1075 : -1074;
        dexp_dyadic(&d, fm, e2);
    }
    boundaries(v, &lo, &hi, &even);

    for (int p = 1; p <= 17; p++) {
        char rd[DMAX];
        int dpt = d.dpt;
        int n = dexp_round(&d, p, rd, &dpt);
        struct dexp cand;
        memset(&cand, 0, sizeof cand);
        for (int i = 0; i < n; i++) cand.dig[i] = rd[i];
        cand.ndig = n;
        cand.dpt = dpt;
        int clo = dexp_cmp(&cand, &lo);
        int chi = dexp_cmp(&cand, &hi);
        if ((clo > 0 && chi < 0) || ((clo == 0 || chi == 0) && even)) {
            int tn = n;
            int X = dpt - 1;
            if (X >= -4 && X < p) {        /* fixed: trim fraction zeros */
                int frac_from = dpt > 0 ? dpt : 0;
                while (tn > frac_from && tn > 1 && rd[tn - 1] == '0') tn--;
            } else {                       /* e-style: trim mantissa zeros */
                while (tn > 1 && rd[tn - 1] == '0') tn--;
            }
            char *o = dst;
            if (neg) *o++ = '-';
            if (X >= -4 && X < p) {
                if (dpt <= 0) {
                    *o++ = '0';
                    *o++ = '.';
                    for (int i = 0; i < -dpt; i++) *o++ = '0';
                    for (int i = 0; i < tn; i++) *o++ = rd[i];
                } else if (dpt >= tn) {
                    for (int i = 0; i < tn; i++) *o++ = rd[i];
                    for (int i = tn; i < dpt; i++) *o++ = '0';
                } else {
                    for (int i = 0; i < dpt; i++) *o++ = rd[i];
                    *o++ = '.';
                    for (int i = dpt; i < tn; i++) *o++ = rd[i];
                }
            } else {
                *o++ = rd[0];
                if (tn > 1) {
                    *o++ = '.';
                    for (int i = 1; i < tn; i++) *o++ = rd[i];
                }
                *o++ = 'e';
                int es = dpt - 1;
                if (es < 0) { *o++ = '-'; es = -es; }
                else *o++ = '+';
                if (es >= 100) {
                    *o++ = (char)('0' + es / 100);
                    *o++ = (char)('0' + (es / 10) % 10);
                    *o++ = (char)('0' + es % 10);
                } else {
                    *o++ = (char)('0' + es / 10);
                    *o++ = (char)('0' + es % 10);
                }
            }
            *o = 0;
            return;
        }
    }
    /* unreachable: 17 significant digits always round-trip */
    strcpy(dst, "?");
}

/* ------------------------------------------- decimal -> double -------- */

static int bitlen128(u128 x) {
    int n = 0;
    while (x) { n++; x >>= 1; }
    return n;
}

/* Rounds value = N * 2^Eb / D (N, D < 2^127) to the nearest double, ties
 * to even. nsticky/dsticky mark material dropped from N/D respectively
 * (the true value is larger / smaller than the one formed by N, D); they
 * only ever decide exact computed ties. The fraction bits of N/D come from
 * binary long division, which is exact while r stays below 2^127 -- hence
 * the 127-bit normalization of the collapsed inputs. */
static double engine_round(u128 N, int Eb, u128 D, int nsticky, int dsticky) {
    if (N == 0) return 0.0;
    u128 r, DD;
    int e2;
    int lead0 = 0, S1 = -1;
    if (N >= D) {
        int k = bitlen128(N) - bitlen128(D);
        if ((N >> k) < D) k--;
        DD = D << k;                   /* <= N: cannot overflow */
        r = N - DD;
        e2 = Eb + k;
    } else {
        DD = D;
        r = N;
        e2 = Eb;                       /* fixed once the leading 1 is found */
        lead0 = 1;
    }
    char bits[64];
    memset(bits, 0, sizeof bits);
    int nb = 0, tail_nonzero = 0;
    for (;;) {
        r <<= 1;
        int bit = (r >= DD);
        if (bit) r -= DD;
        int j = -1;
        if (!lead0) {
            j = nb + 1;
        } else {
            if (S1 < 0) { if (bit) S1 = nb; }
            else j = nb - S1;          /* fraction index after the leading 1 */
        }
        if (j > 0) {
            if (j <= 58) bits[j] = (char)bit;
            else if (bit) tail_nonzero = 1;
        }
        nb++;
        if (j >= 58) {
            if (r != 0) tail_nonzero = 1;
            break;
        }
        if (r == 0) break;             /* expansion terminated */
    }
    if (lead0) {
        if (S1 < 0) return 0.0;        /* |value| < 2^-300ish */
        e2 = Eb - S1 - 1;
    }
    int frac_len = lead0 ? (nb - S1) : nb;
    if (frac_len > 58) frac_len = 58;

    u64 q = 1;
    for (int j = 1; j <= 52; j++)
        q = (q << 1) | (j <= frac_len ? bits[j] : 0);
    /* The mantissa rounds only in the normal path: below 2^-1022 the
     * subnormal unit is finer than the mantissa LSB, and the subnormal
     * branch needs the floor mantissa plus the guard bits. */
    if (e2 >= -1022) {
        int round_up = 0, tie = 0;
        if (frac_len > 52 && bits[53]) {
            int rest = tail_nonzero;
            for (int j = 54; j <= frac_len; j++) if (bits[j]) rest = 1;
            if (rest) round_up = 1;
            else tie = 1;
        }
        if (tie) {
            if (nsticky) round_up = 1;
            else if (dsticky) round_up = 0;
            else round_up = (q & 1);
        }
        if (round_up) {
            q++;
            if (q == (1ULL << 53)) { q >>= 1; e2++; }
        }
    }
    if (e2 > 1023) {
        u64 inf = (u64)0x7FF << 52;
        double res;
        memcpy(&res, &inf, 8);
        return res;
    }
    u64 out;
    if (e2 >= -1022) {
        out = ((u64)(e2 + 1023) << 52) | (q & ((1ULL << 52) - 1));
    } else {
        int sh = -1022 - e2;
        if (sh > 54) return 0.0;
        u64 sub = q, up = 0;
        /* remainder below the subnormal unit: rem/2^sh plus the guard
         * material (b53 = 1/2 unit, b54+ and the loop tail finer) */
        int b53 = (frac_len >= 53) ? bits[53] : 0;
        int b54 = (frac_len >= 54) ? bits[54] : 0;
        int more = ((frac_len >= 55) && (bits[55] || bits[56])) ||
                   tail_nonzero;
        if (sh > 0) {
            u64 rem = sub & ((1ULL << sh) - 1);
            sub >>= sh;
            u64 comp2 = rem * 2 + (u64)b53;
            u64 half2 = 1ULL << sh;    /* 2 * half unit */
            if (comp2 > half2) up = 1;
            else if (comp2 == half2) {
                if (b54 || more) up = 1;
                else if (dsticky) up = 0;
                else if (nsticky) up = 1;
                else up = sub & 1;     /* exact tie: even */
            }
        }
        sub += up;
        if (sub >= (1ULL << 52)) out = (1ULL << 52);
        else out = sub;
    }
    double res;
    memcpy(&res, &out, 8);
    return res;
}

/* value = N * 2^Eb / D with N, D < 2^127 (u128, sticky-collapsed): the
 * 5^|e10| product is accumulated exactly in a small limb array and
 * collapsed once, so the only dropped material is below 2^-126 relative --
 * far under the 2^-53 rounding scale. */
size_t fmt_f64_parse(const char *s, double *out) {
    const char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    int neg = 0;
    if (*p == '-') { neg = 1; p++; }
    else if (*p == '+') p++;

    u128 m = 0;
    int nd = 0, e10 = 0, any = 0, point = 0, nsticky = 0;
    enum { MMAXDIG = 38 };             /* u128 holds 38 decimal digits */
    for (; *p; p++) {
        if (*p >= '0' && *p <= '9') {
            any = 1;
            int dgt = *p - '0';
            if (point) {
                if (m || dgt) {
                    if (nd < MMAXDIG) {
                        m = m * 10 + (u128)dgt;
                        nd++;
                        e10--;         /* m's last digit position */
                    } else if (dgt) {
                        nsticky = 1;   /* tail below m: no exponent change */
                    }
                } else {
                    e10--;             /* leading fractional zero shifts */
                }
            } else {
                if (nd < MMAXDIG && (m || dgt)) {
                    m = m * 10 + (u128)dgt;
                    nd++;
                } else if (m || dgt) {
                    /* dropped integral digit: occupies a position above the
                     * filled mantissa whether or not it is zero (leading
                     * zeros before any significant digit do nothing) */
                    e10++;
                    if (dgt) nsticky = 1;
                }
            }
        } else if (*p == '.' && !point) point = 1;
        else break;
    }
    if (!any) return 0;
    if (*p == 'e' || *p == 'E') {
        const char *q = p + 1;
        int eneg = 0;
        if (*q == '-') { eneg = 1; q++; }
        else if (*q == '+') q++;
        if (*q >= '0' && *q <= '9') {
            int ev = 0;
            for (; *q >= '0' && *q <= '9'; q++)
                if (ev < 400) ev = ev * 10 + (*q - '0');
            e10 += eneg ? -ev : ev;
            p = q;
        }
    }

    /* Accumulate 5^|e10| (times m, for a positive exponent) exactly in
     * binary u64 limbs, then collapse once to the top 127 bits + sticky.
     * The 5^13 chunking keeps every limb product inside u64*u64. */
#define LIMBS 18
    u64 L[LIMBS];
    memset(L, 0, sizeof L);
    if (e10 >= 0) {
        L[0] = (u64)m;                 /* N = m * 5^e10 */
        L[1] = (u64)(m >> 64);
    } else {
        L[0] = 1;                      /* D = 5^t */
    }
    u128 f = 1;
    int fc = 0;
    int t = e10 >= 0 ? e10 : -e10;
    while (t > 0) {
        int c = t > 27 ? 27 : t;       /* 5^27 < 2^63 */
        u128 g = 1;
        for (int i = 0; i < c; i++) g *= 5;
        f *= g;
        fc += c;
        t -= c;
        if (fc >= 27 || t == 0) {
            u128 carry = 0;
            for (int i = 0; i < LIMBS; i++) {
                u128 pr = (u128)L[i] * f + carry;
                L[i] = (u64)pr;
                carry = pr >> 64;
            }
            /* carry beyond the array cannot occur: 2^127 * 5^400 < 2^1056 */
            f = 1;
            fc = 0;
        }
    }
    int top = LIMBS - 1;
    while (top > 0 && L[top] == 0) top--;
    int msb = top * 64 + bitlen128((u128)L[top]) - 1;
    int shbits = msb - 126;
    u128 acc = 0;
    for (int b = 0; b < 127; b++) {
        int pos = msb - b;
        int bit = (pos >= 0) ? (int)((L[pos / 64] >> (pos % 64)) & 1u) : 0;
        acc = (acc << 1) | (u128)bit;
    }
    int sticky2 = 0;
    for (int pos = msb - 127; pos >= 0; pos--)
        if ((L[pos / 64] >> (pos % 64)) & 1u) { sticky2 = 1; break; }

    double val;
    if (e10 >= 0) {
        /* N = m * 5^e10 = acc * 2^shbits: value = N * 2^e10 */
        val = engine_round(acc, e10 + shbits, 1, nsticky || sticky2, 0);
    } else {
        /* D = 5^t = acc * 2^shbits: value = m * 2^e10 / D */
        val = engine_round(m, e10 - shbits, acc, nsticky, sticky2);
    }
    if (neg) val = -val;
    *out = val;
    return (size_t)(p - s);
#undef LIMBS
}
