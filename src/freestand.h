/* freestand.h - the pieces of src/freestand.c other TUs call by name. */

#ifndef FREESTAND_H
#define FREESTAND_H

/* Blocks SIGPIPE by mask (rt_sigprocmask); the write on a peer-closed
   keep-alive socket then returns EPIPE instead of killing the process --
   same effect signal(SIGPIPE, SIG_IGN) has, without libc's signal(). Returns
   0 on success, -1 on failure. */
int fs_ignore_sigpipe(void);

/* Run cmd through /bin/sh -c with stdout+stderr piped to us; returns the read
   end (a pipe fd), or -1. pclose_sh drains-frees and reaps the child. */
int popen_sh(const char *cmd);
int pclose_sh(int fd);

#endif
