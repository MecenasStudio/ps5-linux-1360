#ifndef HV_DEFEAT_1320_H
#define HV_DEFEAT_1320_H

#include <stddef.h>

/*
 * High-firmware (8.xx+) hypervisor defeat, based on the Byepervisor khook
 * escape. See source/hv_defeat_1360.c for the design and PORTING.md for the
 * list of outstanding work.
 */
int hv_defeat_1360(void);

/* Reference khook self-test; see source/hv_defeat_1360.c. */
int khook_selftest(void);

/*
 * Second phase, run after waking from rest mode (once break_hv has disabled
 * NPT): take over the hypervisor from the BSP and boot Linux. Does not return.
 */
int hv_defeat_1360_post_resume(void);

#endif
