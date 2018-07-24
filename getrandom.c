// _GNU_SOURCE should be set before *any* includes.
// Alternatively, pass to compiler with -D, or enable GNU extensions
// with -std=gnu11 (or omit -std completely)
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>

int my_getrandom(void *buf, size_t buflen, unsigned int flags)
{
    return (int)syscall(SYS_getrandom, buf, buflen, flags);
}
