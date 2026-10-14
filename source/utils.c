#include "utils.h"
#include "linux.h"
#include "offsets.h"
#include "byepervisor/kdlsym.h"
#include <fcntl.h>
#include <stdio.h>
#include <sys/cpuset.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>

/* Global Variables */
offset_list env_offset;
uint64_t ktext;
uint64_t kdata;
uint64_t dmap;
uint64_t cr3;
uint32_t fw;
struct linux_info linux_i;

/* Userland pointers to the raw bzImage/initrd mappings, kept alive so the
 * headless HV-boot stager can relocate them into the identity-mapped cave. */
size_t linux_bzimage_len;
/* Paths recorded by fetch_linux() on high firmware, streamed into the cave by
 * stage_hv_boot() without ever mapping the images. */
char linux_bzimage_path[256];
char linux_initrd_path[256];
size_t linux_initrd_len;

int setup_env(void) {
  notify("Welcome to ps5-linux-1360. We'll defeat HV and prepare the system "
         "to boot Linux on sleep resume.\n");
  if (set_offsets())
    return -1;
  if (init_global_vars())
    return -1;
  return 0;
}

int set_offsets(void) {
  fw = (kernel_get_fw_version() >> 0x10) & 0xFFFF;
  if (fw == 0)
    return -1;
  switch (fw) {
  case 0x1360:
    env_offset = off_1360;
    break;
  default:
    return -1;
  }
  return 0;
}

int init_global_vars(void) {
  ktext = KERNEL_ADDRESS_TEXT_BASE;
  kdata = KERNEL_ADDRESS_DATA_BASE;

  /* The Kernel Address Space.
   *
   * Both of these used to be read out of a flat_pmap overlay on the kernel's
   * pmap. On 13.60 the pm_cr3 field is right - measuring the physical address
   * of the level 4 table through it gives 0xcc32000, which is what a CR3 must
   * look like - but pm_pml4 is not, so the direct-map base worked out as
   * dmap = pm_pml4 - pm_cr3 came out as 0x52f4fe0351adfef1, which is not a
   * kernel address at all. Everything routed through pa_to_dmap() then wrote
   * into nowhere: the identity page table, shellcode_hv and the whole Linux
   * image were staged at random addresses, hv_boot loaded a garbage CR3, and
   * the console died the instant the AP ran.
   *
   * So neither value comes from that overlay any more. The direct-map base is
   * the SDK's constant, and cr3 is read from pmap_store + 0x28, which is where
   * the reference payload reads it from and which is known to work. Both are
   * printed by verify_hv_staging() so the next person can see they agree. */
  flat_pmap kernel_pmap;
  uint64_t pmap_store = kdlsym(KERNEL_SYM_PMAP_STORE);

  kread(getpmap(kernel_get_proc(0)), &kernel_pmap, sizeof(kernel_pmap));
  if (kernel_pmap.pm_cr3 == 0)
    return -1;

  cr3 = pmap_store ? kread64(pmap_store + 0x28) : kernel_pmap.pm_cr3;
  dmap = kdldmap(0);

  return 0;
}

uint64_t get_offset_va(uint64_t offset) { return ktext + offset; }

uint64_t get_pml4(uint64_t pmap) { return kread64(pmap + 0x20); }

uint64_t getpmap(uint64_t proc) {
  uint64_t vm = kread64(proc + KERNEL_OFFSET_PROC_P_VMSPACE);
  uint64_t vm_pmap = kread64(vm + env_offset.VMSPACE_VM_PMAP);
  return vm_pmap;
}

// for ring3
uint64_t vtophys_user(uint64_t va) {
  uintptr_t self_pmap = getpmap(kernel_get_proc(getpid()));
  uintptr_t self_pml4 = get_pml4(self_pmap);
  uint64_t pa = vtophys_custom(va, self_pml4 & 0xFFFFFFFF);
  return pa;
}

// for ring0
uint64_t vtophys(uint64_t va) { return vtophys_custom(va, cr3); }

// Source: PS5_kldload
uint64_t vtophys_custom(uint64_t va, uint64_t cr3_custom) {
  uint64_t table_phys = cr3_custom & 0xFFFFFFFF;

  for (int level = 0; level < 4; level++) {
    int shift = 39 - (level * 9);
    uint64_t idx = (va >> shift) & 0x1FF;
    uint64_t entry;

    kread(dmap + PAGE_PA(table_phys) + idx * 8, &entry, sizeof(entry));

    if (!PAGE_P(entry))
      return 0;

    if ((level == 1 || level == 2) && PAGE_PS(entry)) {
      uint64_t page_size = P_SIZE(level);
      return PAGE_PA(entry) | (va & (page_size - 1));
    }

    if (level == 3)
      return PAGE_PA(entry) | (va & 0xFFF);

    table_phys = PAGE_PA(entry);
  }
  return 0;
}

uint64_t pa_to_dmap(uint64_t pa) { return dmap + pa; }

// Set RW bit on all levels if needed and remove eXecute Only bit
void page_chain_set_rw(uint64_t va) {
  uint64_t table_phys = cr3;

  for (int level = 0; level < 4; level++) {
    int shift = 39 - (level * 9);
    uint64_t idx = (va >> shift) & 0x1FF;
    uint64_t entry_va = dmap + PAGE_PA(table_phys) + idx * 8;
    uint64_t entry;

    // Read Level X entry
    kread(entry_va, &entry, sizeof(entry));

    if (!PAGE_P(entry))
      return;

    uint8_t update = 0;
    // Set RW bit on this level
    if (!PAGE_RW(entry)) {
      PAGE_SET_RW(entry);
      update = 1;
    }
    // Unset XO on this level
    if (PAGE_XO(entry)) {
      PAGE_CLEAR_XO(entry);
      update = 1;
    }
    if (update) {
      kwrite(entry_va, &entry, sizeof(entry));
    }

    if (((level == 1 || level == 2) && PAGE_PS(entry)) || (level == 3)) {
      return;
    }

    table_phys = PAGE_PA(entry);
  }
  return;
}

// Remove Global bit on last level
uint64_t page_remove_global(uint64_t va) {
  uint64_t table_phys = cr3;

  for (int level = 0; level < 4; level++) {
    int shift = 39 - (level * 9);
    uint64_t idx = (va >> shift) & 0x1FF;
    uint64_t entry_va = dmap + PAGE_PA(table_phys) + idx * 8;
    uint64_t entry;

    // Read Level X entry
    kread(entry_va, &entry, sizeof(entry));

    if (!PAGE_P(entry))
      return 0;

    if ((level == 1 || level == 2) && PAGE_PS(entry)) {
      PAGE_CLEAR_G(entry);
      kwrite(entry_va, &entry, sizeof(entry));

      uint64_t page_size = P_SIZE(level);
      return PAGE_PA(entry) | (va & (page_size - 1));
    }

    if (level == 3) {
      PAGE_CLEAR_G(entry);
      kwrite(entry_va, &entry, sizeof(entry));

      return PAGE_PA(entry) | (va & 0xFFF);
    }

    table_phys = PAGE_PA(entry);
  }
  return 0;
}

/*
 * Pin to a core, using the numbering this console actually has.
 *
 * The obvious version - mask[0] = 1 << n - is wrong here and is the reason the
 * khook never fired: it pins to a different core than the one kh_set_core()
 * writes the TSS IST slot for, so the #DB is delivered on a core whose IST6 is
 * zero and the pivot pops garbage. The reference payload carries the same
 * warning, kept verbatim below, and pins with 15 - n instead. It also joins a
 * fresh cpuset first, which the working payload does and which the version
 * replaced here did not.
 */
int pin_to_core(int num) {
  uint64_t mask[2] = {};
  cpusetid_t new_id;

  if (cpuset(&new_id)) {
    return 1;
  }

  mask[0] = 0xFFFF;
  mask[1] = 0;
  cpuset_setaffinity(3, 3, new_id, 8, (const cpuset_t *)mask);

  /* Sony system so code that makes sense must be commented out */
  // mask[0] = (1 << num);
  mask[0] = 1 << (15 - num);
  mask[1] = 0;
  return cpuset_setaffinity(3, 1, -1, 0x10, (const cpuset_t *)mask);
}

int pin_to_first_available_core(void) {
  for (int i = 0; i < 16; i++)
    if (pin_to_core(i) == 0)
      return i;
  return -1;
}

void unpin(void) {
  uint64_t m[2] = {0xFFFF, 0};
  cpuset_setaffinity(3, 1, -1, 0x10, (const cpuset_t *)m);
}

/* Path of the on-disk log. /data is writable on every console and survives a
 * reboot, which matters because a hang takes the other two channels with it:
 * the on-screen notification is invisible when the display never comes up, and
 * stdout only reaches the sender while elfldr's connection is alive. A file
 * written before the hang can still be read over FTP afterwards. */
/* Where the progress log goes.
 *
 * /data/ alone was not enough. It reads fine after the S3 resume - that is how
 * the Linux images are loaded - but writes to it stop working at the same point,
 * so every log ended at the last poll before the sleep and the entire
 * post-resume phase was invisible. The buffering added earlier had nothing to
 * flush into: not one append succeeded after the wake.
 *
 * The USB stick is the way out. The console automounts removable storage, and
 * the same stick carries the Linux root filesystem, so it is in the machine
 * anyway and its FAT partition can be read on a Mac afterwards without any
 * special tools. Paths are tried in order and every one that opens is written;
 * /data/ stays last as a fallback. */
static const char *const notify_log_paths[] = {
    "/mnt/usb0/ps5-linux-1360.log",
    "/mnt/usb1/ps5-linux-1360.log",
    "/mnt/usb0/PS5/ps5-linux-1360.log",
    "/data/ps5-linux-1360.log",
    NULL,
};

/* Reported once, on the line after the first message, and it names every path
 * with whether it opened. "No log appeared" and "the log went somewhere else"
 * must not be confusable, and neither must "the new build never ran". */
static int notify_log_reported;
static int notify_log_status[8];

/* Append one message, opening and closing each time. Unbuffered on purpose:
 * stdio would hold the last lines in a buffer that a hang never flushes, and
 * the lines worth having are exactly the ones right before it.
 *
 * After the S3 resume the file is not writable yet. The same thing that makes
 * the first bzImage read return zero bytes makes this open fail, and it clears
 * on its own a few seconds later - the read needed thirty retries to get
 * through it. Lines written inside that window used to be dropped, which is why
 * every log ended at the last poll before the sleep and nothing after it was
 * ever recorded, however far the boot got.
 *
 * They are held here instead and written out as soon as an append succeeds, so
 * the post-resume phase ends up in the file after all. The file survives a
 * power-off, so this is what makes that phase observable at all. */
static void notify_log(const char *msg) {
  static char pending[8192];
  static size_t pending_len;
  size_t len = strlen(msg);
  int wrote_any = 0;

  for (int i = 0; notify_log_paths[i]; i++) {
    int fd = open(notify_log_paths[i], O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
      notify_log_status[i] = -1;
      continue;
    }
    notify_log_status[i] = 1;

    size_t off = 0;
    while (off < pending_len) {
      ssize_t n = write(fd, pending + off, pending_len - off);
      if (n <= 0)
        break;
      off += n;
    }
    off = 0;
    while (off < len) {
      ssize_t n = write(fd, msg + off, len - off);
      if (n <= 0)
        break;
      off += n;
    }
    fsync(fd);
    close(fd);
    wrote_any = 1;

  }

  if (wrote_any) {
    pending_len = 0;
    return;
  }

  /* Nothing is writable at the moment - keep the lines for when something is. */
  if (pending_len + len < sizeof(pending)) {
    memcpy(pending + pending_len, msg, len);
    pending_len += len;
  }
}

void notify(const char *fmt, ...) {
  static char buffer[2048];
  va_list args;

  va_start(args, fmt);
  vsnprintf(buffer, sizeof(buffer), fmt, args);
  va_end(args);

  notify_internal((uint8_t *)buffer);
  notify_log(buffer);
  printf("%s", buffer);

  /* Say once, right after the first message so it cannot be missed above the
   * scrollback, which paths the log could actually be written to. */
  if (!notify_log_reported) {
    notify_log_reported = 1;
    printf("13.60: log paths:");
    for (int i = 0; notify_log_paths[i]; i++)
      printf(" %s=%s", notify_log_paths[i],
             notify_log_status[i] > 0 ? "OK" : "no");
    printf("\n");
  }
}

void notify_internal(uint8_t *msg) {
  struct {
    char pad[45];
    char msg[3075];
  } req;
  bzero(&req, sizeof(req));
  uint64_t len = strlen((const char *)msg) < (sizeof(req.msg) - 1)
                     ? strlen((const char *)msg)
                     : (sizeof(req.msg) - 1);
  memcpy(req.msg, msg, len);
  sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

void enter_rest_mode(void) {
  void *event = NULL;
  sceKernelOpenEventFlag(&event, "SceSystemStateMgrStatus");
  sceKernelNotifySystemSuspendStart();
  sceKernelSetEventFlag(event, 0x400);
  sceKernelCloseEventFlag(&event);
}

// Kit type by EchoStretch
bool if_exists(const char *path) {
  struct stat st;
  return stat(path, &st) == 0;
}

bool sceKernelIsTestKit(void) {
  return if_exists("/system/priv/lib/libSceDeci5Ttyp.sprx");
}

bool sceKernelIsDevKit(void) {
  return if_exists("/system/priv/lib/libSceDeci5Dtracep.sprx");
}

enum kit_type get_kit_type(void) {
  if (sceKernelIsDevKit()) {
    notify("DevKit detected\n");
    return KIT_DEVKIT;
  }
  if (sceKernelIsTestKit()) {
    notify("TestKit detected\n");
    return KIT_TESTKIT;
  }
  notify("Retail console detected\n");
  return KIT_RETAIL;
}

uint64_t alloc_page(void) {
  void *page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);

  // Fault it to force physical allocation
  *(uint8_t *)page = 0;

  return vtophys_user((uintptr_t)page);
}

void install_page(uintptr_t pml4, vm_offset_t va, vm_paddr_t pa, int bits) {
  uint64_t entry;

  uintptr_t pml4e = pml4 + pmap_pml4e_index(va) * 8;
  entry = kread64(pml4e);
  if (!PAGE_P(entry)) {
    uint64_t page = alloc_page();
    entry = page | PG_B_RW | PG_B_P | bits;
    kwrite64(pml4e, entry);
  }

  uintptr_t pdpe = pa_to_dmap(PAGE_PA(entry)) + pmap_pdpe_index(va) * 8;
  entry = kread64(pdpe);
  if (!(entry & PG_B_P)) {
    uint64_t page = alloc_page();
    entry = page | PG_B_RW | PG_B_P | bits;
    kwrite64(pdpe, entry);
  }

  uintptr_t pde = pa_to_dmap(PAGE_PA(entry)) + pmap_pde_index(va) * 8;
  entry = kread64(pde);
  if (!(entry & PG_B_P)) {
    uint64_t page = alloc_page();
    entry = page | PG_B_RW | PG_B_P | bits;
    kwrite64(pde, entry);
  }

  uintptr_t pte = pa_to_dmap(PAGE_PA(entry)) + pmap_pte_index(va) * 8;
  entry = pa | PG_B_RW | PG_B_P | bits;
  pte_store(pte, entry);
}

void pte_store(uintptr_t ptep, uint64_t pte) {
  static_assert((PAGE_SIZE % 0x1000) == 0,
                "PAGE_SIZE should be a multiple of 0x1000");

  for (uint64_t i = 0; i < (PAGE_SIZE / 0x1000); i++) {
    kwrite64(ptep + i * 8, pte + i * 0x1000);
  }
}

void install_page_syscore(vm_offset_t va, vm_paddr_t pa, int bits) {
  uintptr_t syscore_pmap = getpmap(kernel_get_proc(MINI_SYSCORE_PID));
  uintptr_t syscore_pml4 = kread64(syscore_pmap + 0x20);
  install_page(syscore_pml4, va, pa, bits);
}
