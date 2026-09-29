/* start.c - the pre-main bootstrap that replaced picolibc's crt0-linux.o.
 *
 * `_start` is file-scope asm in `.init.start`; src/pico.ld KEEP-sorts every
 * `.init.*` section, and ".start" sorts after ".idle", so idle_text_lo stays
 * the first marker of the text segment and the whole bootstrap lands inside
 * the range idle_sleep drops (src/idle.c). Anything written before the linker
 * script's writable mark is assumed clean by that drop, so nothing in this
 * file may write memory before main() runs except the canary seed below.
 *
 * There is no libc here and no TLS: the program is single-threaded, so errno
 * and the stack-guard are plain .bss variables.
 */

#include <stddef.h>
#include <stdint.h>
#include "freestand.h"

#if defined(__x86_64__)
__asm__(".section .init.start,\"ax\"\n"
        ".globl _start\n"
        ".type _start,@function\n"
        "_start:\n"
        "  mov %rsp, %rdi\n"           /* [sp] = argc, then argv, NULL, envp  */
        "  and $-16, %rsp\n"           /* kernel leaves rsp 16B-aligned       */
        "  sub $8, %rsp\n"             /* fake the return-address slot        */
        "  call p_main\n"
        "  ud2\n"                      /* p_main never returns                */
        ".section .note.GNU-stack,\"\",@progbits\n");
#elif defined(__aarch64__)
/* At process entry aarch64 sp is 16B-aligned; bl leaves sp untouched and puts
   the return address in x30, which p_main's C frame handles itself. */
__asm__(".section .init.start,\"ax\"\n"
        ".globl _start\n"
        "_start:\n"
        "  mov x0, sp\n"
        "  bl p_main\n"
        "  brk #0\n"                   /* p_main never returns                */
        ".section .note.GNU-stack,\"\",@progbits\n");
#else
#error "start.c: aarch64 and x86_64 only"
#endif

/* GCC >= 11 can drop the canary from exactly the one function that runs
   before the guard is seeded. On older gcc the attribute is unknown, so the
   guard stays 0 in .bss and nothing is seeded: that still detects a classic
   overwrite (any non-zero payload moves the frame's canary), just not one
   that hits the seed. */
#if defined(__GNUC__) && __GNUC__ >= 11
#define PMAIN_NOSP __attribute__((no_stack_protector))
#else
#define PMAIN_NOSP
#endif

/* used + externally_visible: the canary machinery (this fail call, and the
   reads of __stack_chk_guard below it) is emitted by the backend at
   codegen time, which is after LTO's resolution/elimination has run -- see
   the `.text.x __stack_chk_fail` link failure a plain definition produced.
   Keeping the definition and its global name in every one of the -flto
   links is all these two attributes are for. */
#define FS_KEEP __attribute__((used, externally_visible))

FS_KEEP
unsigned long __stack_chk_guard;
char **environ;

/* The block the x86_64 TLS guard reads its canary from (%fs:0x28). 64 bytes is
   the shape of a TCB; it lives in .bss, which shares the one dirty data page
   idle_sleep keeps, so pointing FS at it costs nothing at rest. The canary
   value itself is the same AT_RANDOM secret that seeds __stack_chk_guard, so
   both guard kinds share one unpredictable value. */
static unsigned char fs_block[64] __attribute__((aligned(64)));

int main(int argc, char **argv);
void *memcpy(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);

/* _Noreturn so the noreturn callers (__stack_chk_fail, p_main) do not warn
   "noreturn function does return" when GCC cannot prove the raw-exit path. */
static __attribute__((noreturn)) void p_exit_now(int code) {
    long r;
#if defined(__x86_64__)
    __asm__ volatile ("syscall" : "=a"(r) : "a"(231), "D"(code) : "rcx", "r11", "memory");
#elif defined(__aarch64__)
    register long x8 __asm__("x8") = 94;
    register long x0 __asm__("x0") = code;
    __asm__ volatile ("svc 0" : "+r"(x0) : "r"(x8) : "memory");
    r = x0;
#endif
    (void)r;
    for (;;) __builtin_unreachable();
}

__attribute__((noreturn)) void _exit(int code) { p_exit_now(code); }

__attribute__((noreturn)) void exit(int code) { p_exit_now(code); }

__attribute__((noreturn)) void abort(void) { p_exit_now(134); }

/* Killing via exit_group would leave a half-open keep-alive socket to TIME
   WAIT behind a test run, so the one caller that cares (the arena refusal)
   prints its own message first and then exits the whole group. */
FS_KEEP
__attribute__((noreturn)) void __stack_chk_fail(void) {
    static const char msg[] = "stack smashing detected\n";
    long r;
#if defined(__x86_64__)
    __asm__ volatile ("syscall"
                      : "=a"(r)
                      : "a"(1L), "D"(2L), "S"(msg), "d"(sizeof msg - 1)
                      : "rcx", "r11", "memory");
#elif defined(__aarch64__)
    register long x8 __asm__("x8") = 64;
    register long x0 __asm__("x0") = 2;
    register long x1 __asm__("x1") = (long)msg;
    register long x2 __asm__("x2") = sizeof msg - 1;
    __asm__ volatile ("svc 0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
#endif
    (void)r;
    p_exit_now(134);
}

/* getenv: a walk of environ; no setenv/unsetenv caller exists. */
char *getenv(const char *name) {
    if (!name || !name[0]) return NULL;
    for (char **e = environ; e && *e; e++) {
        const char *p = *e, *n = name;
        while (*p && *p == *n && *n != '=') { p++; n++; }
        if (*p == '=' && *n == 0 && p != *e) return (char *)p + 1;
    }
    return NULL;
}

/* The bootstrap: only the inline-asm `_start` above (and src/pico.ld's
   ENTRY) reference it by name -- text outside the compiler's IR -- so both
   `used` (LTO must not skip codegen for an IR-unreferenced function) and
   `externally_visible` (LTO must not internalize/rename the symbol the asm
   names) are required. And it precedes the canary seed, so it must be
   un-protected: see PMAIN_NOSP. */
PMAIN_NOSP __attribute__((noreturn, used, externally_visible)) void p_main(long *sp) {
    long argc = sp[0];
    char **argv = (char **)(sp + 1);
    char **envp = argv + argc + 1;
    environ = envp;

    /* auxv sits one NULL past envp; AT_RANDOM (25) is 16 kernel-random bytes
       and seeds the canary. Finding it by walking pairs (type, value) is what
       the linker/ABI dictates, nothing here may read past AT_NULL (0). */
    char **e = envp;
    while (*e) e++;
    const unsigned long *aux = (const unsigned long *)(e + 1);
    unsigned long seed = 0;
    for (; aux[0]; aux += 2) {
        if (aux[0] == 25 && aux[1]) {
            memcpy(&__stack_chk_guard, (const void *)(uintptr_t)aux[1],
                   sizeof __stack_chk_guard);
            seed = __stack_chk_guard;
        }
    }
    /* BearSSL is compiled at default flags, so its canaries read %fs:0x28,
       which on this link is unmapped. Point FS at the block first, then fill
       the slot -- in that order, so no canary load can ever see a zero. A
       zero canary is what the x86_64 guard treats as "nothing to check"; if
       auxv carried no AT_RANDOM the secret falls back to a fixed nonzero
       value, which is weaker but still a real comparison. */
    if (fs_set_tls_block(fs_block) == 0) {
        memcpy(fs_block + 40, &seed, sizeof seed);
        if (seed == 0) memset(fs_block + 40, 0xa5, sizeof seed);
    }

    exit(main((int)argc, argv));
}
