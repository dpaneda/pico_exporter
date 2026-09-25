#ifndef IDLE_H
#define IDLE_H

/* The sleep between push cycles. idle_sleep() first evicts every page that is
   dead until the next cycle -- the binary's code and read-only data, the TLS
   handshake context, the stack below the sleeping frame -- and then sleeps.
   Of the binary's code, only the page holding idle_sleep stays resident (the
   dirty data page, the TLS session pages and the top of the stack do too).
   Call idle_stack_floor() once, from the frame that will do the sleeping,
   before the first idle_sleep(). */

void idle_stack_floor(void);
void idle_sleep(long ms);

#endif
