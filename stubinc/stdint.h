/* Freestanding <stdint.h> stub: x86_64-elf-gcc ships a wrapper that does
 * #include_next <stdint.h> expecting newlib, which is not installed. */
#ifndef _STUB_STDINT_H
#define _STUB_STDINT_H
typedef signed char        int8_t;
typedef unsigned char      uint8_t;
typedef short              int16_t;
typedef unsigned short     uint16_t;
typedef int                int32_t;
typedef unsigned int       uint32_t;
typedef long long          int64_t;
typedef unsigned long long uint64_t;
typedef long               intptr_t;
typedef unsigned long      uintptr_t;
typedef long long          intmax_t;
typedef unsigned long long uintmax_t;
#define INT8_MAX 127
#define UINT8_MAX 255
#define INT16_MAX 32767
#define UINT16_MAX 65535
#define INT32_MAX 2147483647
#define UINT32_MAX 4294967295U
#define INT64_MAX 9223372036854775807LL
#define UINT64_MAX 18446744073709551615ULL
#endif
