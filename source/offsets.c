#include "offsets.h"

/*
 * 13.60 only.
 *
 * This file used to carry 23 more tables, one per firmware from 3.00 to 13.20,
 * for the ACPI-wakeup path and for the 13.20 high-firmware escape. All of those
 * vectors have been removed: they cannot run on a 13.60 console, and every one of
 * them was a set of offsets that had to be kept in mind whenever anything here
 * changed. Only the table this port uses is left.
 *
 * Every value in it is marked with where it came from - HW for read back from
 * this console through elfldr, SIG for identified by a signature the target
 * carries, TAB for taken from kstuff's 13.60 table and confirmed here. All 31 the
 * escape uses were verified with the offset verifier kept alongside the dumps,
 * outside this repository: it re-reads every value from the console's own kernel
 * and hypervisor images.
 */
offset_list off_1360 = {
    /* ===== Firmware 13.60 ===============================================
     *
     * Every value below was checked against this console's own 13.60 kernel
     * rather than copied from another firmware's table. Three sources:
     *
     *   HW    read back from the live kernel through elfldr
     *   SIG   identified by a signature the target carries itself
     *   BYEP  Byepervisor-Reborn's include/offsets/13_60.h, which is complete
     *         for the escape and is cross-checked here where possible
     *
     * 53 of the 64 fields are filled. The eleven left at 0 are either not on
     * the escape path (see check_offsets() in hv_defeat_1360.c) or belong to
     * display and WiFi bring-up, which a headless boot does not need.
     */
    /* HW: confirmed on this console. With 0x2E8 the pmap yields cr3 =
     * 0xcc32000, a physical address as CR3 must be; with 0x1D8 it yields
     * 0x6ff558000, which has high bits set and cannot be one.
     *
     * NOTE: the upstream high-firmware port and Byepervisor both hardcode 0x1D8
     * for 13.00/13.20/
     * 13.60. The CR3 measurement disagrees. If you port 13.60 and see odd
     * pmap behaviour, this is the first field to question. */
    .VMSPACE_VM_PMAP = 0x2E8,
    .ACPIGBL_FACS = 0x39C9490,        /* SIG: the qword the ACPICA mapper stores the mapped FACS into */
    .IDT = 0x3BB4300,                 /* SIG: 256 present interrupt gates; BYEP agrees */
    .COMMON_TSS = 0x3BB6FE0,          /* SIG: rsp0 at +4 is a kernel stack pointer; BYEP agrees */
    .FUN_MEMCPY = 0x259BE0,           /* SIG: kstuff's rep_movsb_pop_rbp_ret is this function's tail */
    .GAD_ADD_RSP_28_POP_RBP_RET = 0x25213E,  /* BYEP: add rsp,0x28 ; ret */
    .GAD_IRETQ = 0x257B3D,            /* BYEP + TAB: kstuff's doreti_iret, Byepervisor's IRETQ */
    .GAD_POP_RAX_RET = 0x2912A1,      /* BYEP: pop rax ; ret */
    .GAD_POP_RDI_RET = 0x28CE6D,      /* BYEP: pop rdi ; ret */
    .GAD_POP_RSI_RET = 0x34CB91,      /* BYEP: pop rsi ; ret */
    .GAD_POP_RDX_RET = 0x2A0F7B,      /* BYEP: pop rdx ; ret */
    .GAD_POP_RCX_RET = 0x2918B2,      /* BYEP: pop rcx ; ret */
    .GAD_POP_RSP_RET = 0x291C42,      /* BYEP: pop rsp ; ret */
    .HOOK_ACPI_WAKEUP_MACHDEP = 0x3913B0,        /* BYEP: KERNEL_SYM_ACPI_SLEEP_MACHDEP_HOOK */
    .KERNEL_CODE_CAVE = 0x2D39000,    /* BYEP: same value the data cave uses on high FW */
    .FUN_PRINTF = 0x4ADD60,           /* HW: prologue read back from the live kernel */
    .FUN_SMP_RENDEZVOUS = 0xB03BA0,   /* SIG: 4-arg wrapper, loads all_cpus and jmps smp_rendezvous_cpus */
    /* Possibly obsolete on this vector: the Byepervisor khook does not use a
     * fixed VMEXIT cave. Kept because they verified as real. */
    .HV_CODE_CAVE_PA = 0x62806F00,    /* HW: 4096 bytes of 0xcc in the hypervisor dump */
    .HV_HANDLE_VMEXIT_PA = 0x6283D800,/* HW: mov edx,0xcfc ; in eax,dx */
    .KERNEL_UART_OVERRIDE = 0,        /* not on the escape path; the one hard gap for kernel prep */
    .KERNEL_CFI_CHECK = 0x44F8C0,     /* SIG: prints cfi_check_fail with (data, caller, callee); 7315 call sites */
    .G_VBIOS = 0x3DDB9F0,             /* SIG: PCI ROM signature then "113-AMDOBP-006" and AMD ATOMBIOS */
    .FUN_TRANSMITTER_CONTROL = 0,     /* display bring-up; not needed headless */
    .FUN_MP3_INITIALIZE = 0xA13740,   /* SIG: "[MP3] failed to init message thread", reached via one stub */
    .FUN_MP3_INVOKE = 0,              /* display bring-up; not needed headless */
    .PS5_WIFI_FW_OFFSET = 0,          /* WiFi; not needed to boot */
    .PS5_WIFI_FW_SIZE = 0,            /* WiFi; not needed to boot */
    .KERNEL_SYM_DMPML4I = 0x3B49294,  /* BYEP */
    .KERNEL_SYM_DMPDPI = 0x3B49298,   /* BYEP */
    .KERNEL_SYM_PML4PML4I = 0x3B47E4C,/* BYEP */
    .KERNEL_SYM_SYS_GETUID = 0x2A8D60,/* BYEP */
    .KERNEL_SYM_HV_MP_STARTUP_CALL = 0xC16EE0,      /* BYEP: the khook target */
    .KERNEL_SYM_MP_STARTUP_INIT_VECTOR = 0x269FB8,  /* BYEP */
    .KERNEL_SYM_PMAP_STORE = 0x3B48FF8,             /* BYEP */
    .KERNEL_SYM_DATA_CAVE = 0x2D39000,              /* BYEP */
    .HV_SYM_HEAP_BASE = 0x83028,      /* BYEP */
    .HV_SYM_PCPUS = 0x82A60,          /* BYEP */
    /* The hypervisor's loader base. Held 0x062800000 (24.6 GiB) until now, which is
     * what Byepervisor's table carries and what the e820 map in boot_linux.c
     * reserves, and it cannot be right on 13.60: the two addresses below that were
     * measured on this console - HV_CODE_CAVE_PA and HV_HANDLE_VMEXIT_PA, both at
     * 0x628xxxxx - would then lie sixteen times below their own base. One value is
     * missing a zero, and it is this one.
     *
     * It matters because hv_base_pa() feeds hv_base + HV_SYM_HEAP_BASE and
     * hv_base + HV_SYM_PCPUS into the khook's action chain: sixteen times too high
     * puts the hypervisor's heap and per-CPU pointers into whatever lives at 24.6
     * GiB, which is not the hypervisor. The escape still fires, because the VMEXIT
     * patch uses the absolute addresses above, but the hypervisor's own state is
     * left inconsistent - and the handover dies right after the takeover, every
     * time, in the log's fifteen out of fifteen. */
    .HV_LOADER_PA_REGULAR = 0x62800000,   /* HW: 16x below the BYEP value; see above */
    .HV_LOADER_PA_PRO = 0x8e0800000,      /* BYEP */
    .GAD_POP_R8 = 0xB8CA6D,           /* BYEP: pop r8 ; ret */
    .GAD_STORE_RCX_R8 = 0x474389,     /* BYEP: mov [rcx], r8 ; ret */
    .GAD_OR_RCX_EAX = 0x321EA0,       /* BYEP: or [rcx], eax ; ret */
    .GAD_SET_DR7 = 0xA07BA6,          /* BYEP: mov dr7,rax ; mov eax,r8d ; ret */
    .GAD_ST_RCX_RAX = 0x2BB28F,       /* BYEP: mov [rcx], rax ; xor eax,eax ; ret */
    .GAD_STORE_RDI8_RCX = 0x32693F,   /* BYEP: mov [rdi+8], rcx ; ret */
    .GAD_ST_RCX_RDX = 0x82B915,       /* BYEP: mov [rcx], rdx ; ret */
    .GAD_MOV_RAX_RSI = 0x8E3A44,      /* BYEP: mov rax, rsi ; ret */
    .GAD_MOV_RAX_RDI = 0xBECDEA,      /* BYEP: mov rax, rdi ; ret */
    .GAD_REP_MOVSB = 0x25D027,        /* BYEP: rep movsb ; nop ; rep ret */
    .GAD_CLD = 0x30644F,              /* BYEP: cld ; ret */
    .GAD_RET_TRAMP = 0x2912A2,        /* BYEP: ret */
    .GAD_DBREG_RESUME = 0x2529D8,     /* BYEP: resumectx tail */
};
