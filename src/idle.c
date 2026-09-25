/* idle.c - evict everything dead until the next cycle, then sleep.
 *
 * Raw syscalls on purpose: a call into picolibc's madvise()/nanosleep() would
 * keep their text pages resident through the sleep. With everything inlined
 * here, the only code page left resident while the process sleeps is this one.
 */

#include <stddef.h>
#include <stdint.h>

#include "bearglue.h"
#include "idle.h"

/* The binaries are linked with -Wl,-z,max-page-size=0x1000 (Makefile) and
   cannot load on a 16K/64K-page kernel anyway. It must be right: madvise
   rounds len up to the real page size, so a smaller PAGE here would zero
   live stack. */
#define PAGE 4096UL
#define PFLOOR(a) ((uintptr_t)(a) & ~(PAGE - 1))
#define PCEIL(a)  (((uintptr_t)(a) + PAGE - 1) & ~(PAGE - 1))

/* From picolibc_linux.ld: the text segment is .init then .text, closed by
   etext; _pid_base is ADDR(.rodata); the first byte the program ever writes
   is the lower of __tls_space (errno) and __data_start. Everything below that
   byte in the RW segment is clean file data and safe to drop.
   The script exports no symbol for the segment's first byte. On x86_64 crt0
   places _start in plain .text, sorted after main, so _start is not reliably
   the segment start; the marker is: an empty .init.* input section, KEEP'd
   and first in the segment. */
__asm__(".pushsection .init.idle,\"ax\"\n"
        ".globl idle_text_lo\n"
        "idle_text_lo:\n"
        ".popsection");
extern char idle_text_lo[], etext[], _pid_base[], __data_start[], __tls_space[];

#define MADV_DONTNEED_ 4

#if defined(__x86_64__)
#define SYS_madvise_   28
#define SYS_nanosleep_ 35
__attribute__((always_inline)) static inline long
sys3(long n, long a, long b, long c) {
    long r;
    __asm__ volatile ("syscall"
                      : "=a"(r)
                      : "a"(n), "D"(a), "S"(b), "d"(c)
                      : "rcx", "r11", "memory");
    return r;
}
#elif defined(__aarch64__)
#define SYS_madvise_   233
#define SYS_nanosleep_ 101
__attribute__((always_inline)) static inline long
sys3(long n, long a, long b, long c) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    __asm__ volatile ("svc 0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}
#endif

#if defined(__x86_64__)
__attribute__((always_inline)) static inline uintptr_t stack_ptr(void) {
    uintptr_t sp;
    __asm__ volatile ("mov %%rsp, %0" : "=r"(sp));
    return sp;
}
#elif defined(__aarch64__)
__attribute__((always_inline)) static inline uintptr_t stack_ptr(void) {
    uintptr_t sp;
    __asm__ volatile ("mov %0, sp" : "=r"(sp));
    return sp;
}
#else
#error "idle.c: aarch64 and x86_64 only"
#endif

static uintptr_t g_stack_low;

/* Touching the bottom of a 32 kB local grows the stack VMA down to it, so
   every deeper frame a cycle uses (collectors, BearSSL) lands inside a range
   that is known to be mapped. Its pages are dropped by the first idle. */
#define STACK_PROBE 32768
__attribute__((noinline)) void idle_stack_floor(void) {
    volatile char probe[STACK_PROBE];
    probe[0] = 0;
    g_stack_low = PFLOOR(&probe[0]);
}

__attribute__((always_inline)) static inline void drop(uintptr_t lo, uintptr_t hi) {
    if (hi > lo) sys3(SYS_madvise_, (long)lo, (long)(hi - lo), MADV_DONTNEED_);
}

/* no_stack_protector keeps this leaf free of any reference outside its page:
   the canary epilogue only calls __stack_chk_fail on a mismatch, and the
   guard it reads is in the resident .bss page, but the call target is code
   that must not be needed here. GCC >= 11; older compilers warn and keep the
   canary, which costs nothing at rest. */
__attribute__((aligned(4096), noinline, no_stack_protector))
void idle_sleep(long ms) {
    struct { long tv_sec, tv_nsec; } ts;
    if (ms <= 0) return;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;

    if (bg_hs_base) drop((uintptr_t)bg_hs_base, (uintptr_t)bg_hs_base + bg_hs_len);

    /* Nothing live sits below sp except the x86-64 red zone (128 B; aarch64
       has none, the margin is harmless there), so whole pages below that are
       dead. The guard is not optional: before idle_stack_floor, 0..sp would
       zero-fill .data, .bss, the arena and the TLS session. */
    if (g_stack_low) drop(g_stack_low, PFLOOR(stack_ptr() - 128));

    uintptr_t wr = (uintptr_t)__tls_space < (uintptr_t)__data_start
                       ? (uintptr_t)__tls_space : (uintptr_t)__data_start;
    drop(PCEIL(_pid_base), PFLOOR(wr));

    /* Around this function's own page, never through it: refaulting it on
       the next instruction would trigger the kernel's fault-around, which
       maps up to 16 neighbouring page-cache pages straight back in. */
    uintptr_t self = PFLOOR((uintptr_t)idle_sleep);
    drop(PFLOOR(idle_text_lo), self);
    drop(self + PAGE, PCEIL(etext));

    /* EINTR is ignored, as msleep did: no handlers are installed, and
       SIGSTOP/SIGCONT restarts the call. */
    sys3(SYS_nanosleep_, (long)&ts, 0, 0);
}
