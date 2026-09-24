/* sysinfo.h is included for glibc/musl compatibility but unused by the
 * picolibc deployable; provide an empty guarded header so the build never
 * falls through to the cross-gcc (glibc) sys/sysinfo.h. */
#ifndef _SYS_SYSINFO_H_
#define _SYS_SYSINFO_H_

#endif