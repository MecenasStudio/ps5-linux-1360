#ifndef CONFIG_H
#define CONFIG_H

#define PAGE_SIZE 0x4000ULL

// This is used to allocate resources for HV shellcode and Linux boot
#define cave 0x100000000ULL
#define cave_hv_paging cave
#define cave_hv_code                                                           \
  cave_hv_paging + 0x3000ULL // Leave space for 3 pages but we only use 2 for
                             // 1GB 1:1 mapping
#define cave_linux_files cave_hv_code + 0x2000ULL
#define cave_linux_info cave_linux_files
#define cave_bzImage cave_linux_info + PAGE_SIZE
// #define cave_initrd     // Allocated dynamically after bzImage

#define hv_base_rsp (cave + 0x10000000ULL)
#define hv_stack_size 0x1000ULL

// This is used as transitional storage from ProsperoOS to Kernel shellcode
#define kernel_cave 0xFFFF800000000000
#define kernel_cave_shellcode kernel_cave
#define kernel_cave_shellcode_0761 kernel_cave_shellcode + PAGE_SIZE + PAGE_SIZE
#define kernel_cave_files kernel_cave_shellcode_0761 + PAGE_SIZE
#define kernel_cave_linux_info kernel_cave_files
#define kernel_cave_bzImage kernel_cave_linux_info + PAGE_SIZE

// #define kernel_cave_initrd   // Allocated dynamically after bzImage

// Linux boot config
#define VRAM_SIZE (512ULL * 1024 * 1024)
#define CMD_LINE                                                               \
  "root=/dev/sda2 rw rootwait console=ttyTitania0 console=tty0 "               \
  "video=DP-1:1920x1080@60 mitigations=off idle=halt pci=pcie_bus_perf"

// Single-core launch. One VMMCALL takes one core out of the PS5's kernel and into
// shellcode_hv, and Linux comes up on that core alone with " maxcpus=1 nosmp". The
// other fifteen keep running the PS5, which is deliberate: they are what the
// platform's EC is watching, and a system with no running kernel at all is one it
// powers off.
//
// Hence both effects of this flag are wanted: shellcode_hv must not wait for CPUs
// that are never coming (it would hang), and Linux must not try to bring up APs
// that are still inside the hypervisor.
#define HV_HEADLESS_SINGLE_CORE 1

#define DEBUG 0 // Toggle to 0 to disable logs

#endif
