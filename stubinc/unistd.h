/* Minimal <unistd.h> for the freestanding x86-64 shellcode build.
 *
 * The shellcode is built -nostdlib -ffreestanding and only includes this header
 * for the type names glibc/FreeBSD happen to define in it. A bare-metal
 * x86_64-elf toolchain has no libc headers at all, so the upstream build only
 * worked because it used a Linux-hosted x86-64 gcc. This stands in for it.
 */
#ifndef _STUB_UNISTD_H
#define _STUB_UNISTD_H

#include <stddef.h>
#include <stdint.h>

typedef intptr_t  ssize_t;
typedef intptr_t  off_t;
typedef int32_t   pid_t;
typedef uint32_t  uid_t;
typedef uint32_t  gid_t;
typedef uint32_t  mode_t;

#endif /* _STUB_UNISTD_H */
