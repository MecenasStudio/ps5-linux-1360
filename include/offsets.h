#ifndef OFFSETS_H
#define OFFSETS_H

#include <stdint.h>

typedef struct _offset_list {
  /* Loader utils */
  uint64_t VMSPACE_VM_PMAP;
  /* Offsets for 5.00-6.02 hv exploit */
  uint64_t ACPIGBL_FACS;
  uint64_t IDT;
  uint64_t COMMON_TSS;
  uint64_t FUN_MEMCPY;
  uint64_t GAD_ADD_RSP_28_POP_RBP_RET;
  uint64_t GAD_IRETQ;
  uint64_t GAD_POP_RAX_RET;
  uint64_t GAD_POP_RDI_RET;
  uint64_t GAD_POP_RSI_RET;
  uint64_t GAD_POP_RDX_RET;
  uint64_t GAD_POP_RCX_RET;
  uint64_t GAD_POP_RSP_RET;
  /* Shellcode Kernel */
  uint64_t HOOK_ACPI_WAKEUP_MACHDEP;
  uint64_t KERNEL_CODE_CAVE;
  uint64_t FUN_PRINTF;
  uint64_t FUN_SMP_RENDEZVOUS;
  /* Shellcode HV */
  uint64_t HV_CODE_CAVE_PA;
  uint64_t HV_HANDLE_VMEXIT_PA;
  /* Patches on Kernel */
  uint64_t KERNEL_UART_OVERRIDE;
  uint64_t KERNEL_CFI_CHECK;
  /* Internal functions to prepare boot */
  uint64_t G_VBIOS;
  uint64_t FUN_TRANSMITTER_CONTROL;
  uint64_t FUN_MP3_INITIALIZE;
  uint64_t FUN_MP3_INVOKE;
  /* Wifi FW */
  uint64_t PS5_WIFI_FW_OFFSET;
  uint64_t PS5_WIFI_FW_SIZE;
  /* High-firmware (8.xx+) Byepervisor vector */
  uint64_t KERNEL_SYM_DMPML4I;
  uint64_t KERNEL_SYM_DMPDPI;
  uint64_t KERNEL_SYM_PML4PML4I;
  uint64_t KERNEL_SYM_SYS_GETUID;
  uint64_t KERNEL_SYM_HV_MP_STARTUP_CALL;
  uint64_t KERNEL_SYM_MP_STARTUP_INIT_VECTOR;
  uint64_t KERNEL_SYM_PMAP_STORE;
  uint64_t KERNEL_SYM_DATA_CAVE;
  uint64_t HV_SYM_HEAP_BASE;
  uint64_t HV_SYM_PCPUS;
  uint64_t HV_LOADER_PA_REGULAR;
  uint64_t HV_LOADER_PA_PRO;
  uint64_t GAD_POP_R8;
  uint64_t GAD_STORE_RCX_R8;
  uint64_t GAD_OR_RCX_EAX;
  uint64_t GAD_SET_DR7;
  uint64_t GAD_ST_RCX_RAX;
  uint64_t GAD_STORE_RDI8_RCX;
  uint64_t GAD_ST_RCX_RDX;
  uint64_t GAD_MOV_RAX_RSI;
  uint64_t GAD_MOV_RAX_RDI;
  uint64_t GAD_REP_MOVSB;
  uint64_t GAD_CLD;
  uint64_t GAD_RET_TRAMP;
  uint64_t GAD_DBREG_RESUME;
} offset_list;

extern offset_list off_1360;

#endif
