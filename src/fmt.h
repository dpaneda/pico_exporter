/* fmt.h - stdio-free formatting and parsing helpers (issue #2).
 *
 * Replaces snprintf/printf/strtod/strtoll on the whole push path: integers
 * render digit by digit, doubles take a shortest round-trip path laid out
 * exactly like the "%.*g"-walk it replaces (the tests byte-match values
 * like 3e+02 and 1.2e+09), and the decimal parser is correctly rounded
 * like strtod. vfprintf/dtoa then fall out of the link.
 */

#ifndef FMT_H
#define FMT_H

#include <stddef.h>
#include <stdint.h>

/* Digit conversion: writes decimal text (no terminating zero), returns the
 * digit count. */
int fmt_u64(char *dst, uint64_t n);
int fmt_i64(char *dst, int64_t n);

/* Appends the decimal text of n / the string s (with its terminating NUL). */
void fmt_u64_append(char **p, uint64_t n);
void fmt_i64_append(char **p, int64_t n);
void fmt_str_append(char **p, const char *s);

/* strtol replacement over [ws] [+-] digits: returns the value and sets
 * *end to the first character not consumed (s itself when no digits). */
long long fmt_parse_ll(const char *s, const char **end);

/* Renders the shortest decimal string that reads back as v, in the same %g
 * notation the "%.*g" walk produced (fixed between 1e-4 and the precision,
 * exponential with a signed 2+-digit exponent otherwise, trailing
 * fractional zeros trimmed). inf/nan render as "inf"/"nan"/"-0" style. */
void fmt_f64_shortest(char *dst, double v);

/* Correctly-rounded strtod replacement over plain decimal constants:
 * [ws] [+-] digits [. digits] [eE [+-] digits]. Returns the number of bytes
 * consumed, 0 on failure; *out is untouched on failure. Hex floats and
 * inf/nan spellings are rejected -- nothing /proc or exposition format
 * carries needs them. */
size_t fmt_f64_parse(const char *s, double *out);

#endif /* FMT_H */
