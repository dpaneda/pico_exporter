/* freestand.h - the pieces of src/freestand.c other TUs call by name. */

#ifndef FREESTAND_H
#define FREESTAND_H

/* Blocks SIGPIPE by mask (rt_sigprocmask); the write on a peer-closed
   keep-alive socket then returns EPIPE instead of killing the process --
   same effect signal(SIGPIPE, SIG_IGN) has, without libc's signal(). Returns
   0 on success, -1 on failure. */
int fs_ignore_sigpipe(void);

/* Points the x86_64 FS base at `base`, a block of at least 64 bytes whose +0x28
   slot the compiler's stack-protector guard reads its canary from. Without it
   a -nostdlib process has no FS base and that read is a SIGSEGV. Returns 0 on
   success, -1 on failure; a no-op returning 0 on aarch64, whose gcc uses the
   global guard instead. */
int fs_set_tls_block(void *base);

/* Run cmd through /bin/sh -c with stdout+stderr piped to us; returns the read
   end (a pipe fd), or -1. pclose_sh drains-frees and reaps the child. */
int popen_sh(const char *cmd);
int pclose_sh(int fd);

#endif
