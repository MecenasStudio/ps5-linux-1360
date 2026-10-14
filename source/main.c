#include "hv_defeat_1360.h"
#include "loader.h"
#include "utils.h"
#include <sys/param.h>
#include <unistd.h>

/* Physical page the action chain installs the AP payload on. Kept in step with
 * the same constant in hv_defeat_1360.c. */
#define STARTUP_MP_PAYLOAD_PAGE 0x3FFFF000ULL

int main(void) {
  if (setup_env()) {
    notify("Something went wrong while initiating.\nPlease make sure your fw "
           "is supported.");
    return -1;
  }

  kernel_set_ucred_authid(getpid(), 0x4800000000000007);
  pin_to_core(0);

#ifndef SKIP_SELFTEST
  /* Reference self-test. It installs the same khook on a function that is called
   * immediately and arms it with kh_trigger, so that a failure of the real hook
   * later can be told apart from a broken #DB path.
   *
   * It arms a hardware execute breakpoint, installs a khook, triggers it and
   * disarms, so it leaves DR0/DR7 and the TSS IST slot touched. Build with
   * -DSKIP_SELFTEST to drop it. */
  if (khook_selftest()) {
    notify("selftest: FAILED; stopping.\n");
    return -1;
  }
  notify("selftest: passed.\n");
#endif

#ifndef SKIP_FETCH_LINUX
  /* Record where the images are; do not load them. This has to happen before the
   * suspend because /data/ and the USB stick are only reliably readable here.
   *
   * Loading them is what stops the console coming back from rest mode: every run
   * with the images resident died after the wake, whatever form they took. So the
   * paths and sizes are recorded and stage_hv_boot() streams from them into the
   * cave after the resume. */
  if (fetch_linux(&linux_i)) {
    notify("Something went wrong while installing linux files.\n");
    return -1;
  }
#endif

  /* There used to be a check here for the images colliding with
   * STARTUP_MP_PAYLOAD_PAGE, the page the action chain copies break_hv onto. It
   * compared the user-space mappings of bzImage and initrd against that address.
   *
   * Nothing is mapped on this path any more: the images are streamed straight
   * into the cave at physical 4 GiB after the resume, and 4 GiB is nowhere near
   * that page, so the check can no longer fail and is gone with the mappings. */


#ifdef DIAG_NO_ESCAPE
  /* Decisive test: load the images and then do nothing else.
   *
   * Every run that has died called fetch_linux(); the one that survived did not.
   * This separates "the images themselves make the suspend fail" from "the
   * images interact with the khook". No hook is installed, nothing is staged,
   * nothing is armed - the payload loads 41 MB, parks, and the only question is
   * whether the console comes back.
   *
   * If it powers off, the khook is not involved and the fault is in the suspend
   * with this much anonymous memory live. If it comes back, the khook plus that
   * memory is the combination to attack. */
  notify("13.60: DIAG_NO_ESCAPE: images loaded, no hook, parking.\n");
  for (;;)
    sleep(30);
#endif

  /* 13.60 only.
   *
   * The 3.00-7.61 vectors and prepare_resume() are gone. They are different
   * firmware with their own offsets and their own shellcode, and this repository
   * is for 13.60; keeping them meant keeping a second, unreachable code path that
   * had to be reasoned about every time something changed. Anything outside the
   * high-firmware range is refused here rather than falling into a vector that
   * cannot work.
   *
   * hv_defeat_1360() arms the hook and loads nothing. All the heavy work happens
   * after the wake, because with the images resident the console powers off after
   * the resume whatever form they take. */
  if (fw < 0x0800 || fw >= 0x1400) {
    notify("13.60: this port handles 13.60 only (fw %#x).\n", fw);
    goto err;
  }

  if (hv_defeat_1360())
    goto err;

  notify("Finished preparation. Going to rest mode in 5 seconds.\nPlease wait "
         "for the orange light to stop "
         "blinking and then wakeup to Linux :)\n");

  sleep(5);

#ifdef MANUAL_SLEEP
  /* Diagnostic: do not ask the system to suspend, leave that to the operator.
   *
   * enter_rest_mode() calls sceKernelNotifySystemSuspendStart() and sets an event
   * flag, which is not the same thing as the operator choosing "Enter Rest Mode"
   * from the PS menu. Byepervisor's payload - the one confirmed to fire on this
   * console - never asks the system to suspend at all; it just parks in a loop
   * and waits to be put to sleep. If the request we make leads into a different
   * suspend path, the S3 resume that re-enters khv_startup_mp may never run.
   *
   * With this build the payload parks and polls instead, so there are ten minutes
   * to put the console to sleep by hand. */
  notify("13.60: MANUAL_SLEEP: put the console to sleep now (PS button -> "
         "Power -> Enter Rest Mode).\n");
#else
  enter_rest_mode();
#endif

  /* On high firmware the console comes back from rest mode with NPT disabled;
   * finish the takeover from here (runs on the BSP once we wake). */
  hv_defeat_1360_post_resume();

  while (1) {
    sleep(30);
  }

  return 0;

err:
  notify("Something went wrong while defeating Hypervisor.\nPlease make sure "
         "your fw is supported.");
  return -1;
}
