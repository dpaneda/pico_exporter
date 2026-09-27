/* Minimal Linux utsname layout (65-byte fields are the Linux standard on
   every arch), shadowing the host header on every link. */
#ifndef _SYS_UTSNAME_H_
#define _SYS_UTSNAME_H_

struct utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

#ifdef __cplusplus
extern "C" {
#endif

int uname(struct utsname *buf);

#ifdef __cplusplus
}
#endif

#endif