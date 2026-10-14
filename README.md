# ps5-linux-1360

Boot Linux on a PS5 running firmware **13.60**, by escaping the hypervisor with the
Byepervisor kernel hook and handing control to a kernel staged in the kernel data
cave.

**13.60 is the only firmware this handles.** The offsets are for it and anything else
is refused at startup with *"make sure your fw is supported"*. Tested on a **Fat**.
The **Slim** loads its hypervisor at the same address and should behave the same,
but has not been tried. The **Pro** is not supported: it loads its hypervisor at
`0x8e0800000` and `hv_base_pa()` does not distinguish the two.

## Where it stands

```
arm the hypervisor hook                  works
resume, kernel hook fires, cookie        works
stage both Linux images in the cave      works, verified byte for byte
check the identity map and the dmap      works, every entry checked
install the VMEXIT redirect              lands where it is written
hand the machine to shellcode_hv         FAILS - platform powers off
```

**It has never been observed to start Linux.** An earlier version of this file said
it reached the initramfs and spent ninety seconds looking for the root filesystem.
That was wrong: the two runs that lived that long are in the payload's own log as
`still no cookie (46/300, 90s)`, meaning the hook had not fired and the payload was
simply polling. There was no kernel and no root filesystem - only a console that had
not powered itself off yet.

**The fault is in the handoff, and it is deterministic.** Of seventy-nine runs in that
log, fifteen reached `takeover armed; firing getuid() -> shellcode_hv` after streaming
and verifying both images - and the console powered off in all fifteen, always in the
same place. It is not `shellcode_hv`: replacing it in the cave with four bytes of
`cli; hlt` changes nothing, so the platform is gone before that code runs.

**What is known about it.** The takeover writes a stub over the hypervisor's VMEXIT
dispatcher, and that dispatcher belongs to the whole machine, not to the one core
that issued the VMMCALL. The other cores are still running the PS5 and issuing
hypercalls continuously, so they land in the stub too - which is why one core kicked
or sixteen makes no difference, why writing the stub later makes no difference, and
why the redirect now delegates instead: the entry is moved by rewriting the host RIP
in the state save area named by `VM_HSAVE_PA`, and everything except our own
hypercall goes to the untouched dispatcher. That is the current state of the code, and
it is as far as the evidence goes. The next measurement needs a console.

**There is no console anywhere on this path.** `shellcode_hv` prints to the UART at
`0xc1010104`, which is the same port the kernel command line already names as
`console=ttyTitania0`, and nothing else in the handoff can report anything: the
payload's log stops at the point control leaves it, the PS5's kernel log stops at
suspend, and `tty0` needs a framebuffer that the missing display bring-up never
creates. A USB-TTL adapter on the console's UART pins would show, in one run, whether
`shellcode_hv` is reached and where it stops - and after that the entire kernel log.
Everything else on this path is already verified and needs no further blind attempts.

## What is not known

- **`FUN_TRANSMITTER_CONTROL` and `FUN_MP3_INVOKE`.** The reference boot path makes
  four bring-up calls before the kernel; this one has `mp3_initialize` and the VBIOS
  copy, which is two. Those two offsets are in no dump, no SDK and no public table for
  13.60, and until the DP link is up `console=tty0` has nowhere to draw. `G_VBIOS` and
  `FUN_MP3_INITIALIZE` are known.
- **Whether the MP3 call is what keeps the platform alive.** The runs in which
  `mp3_initialize(0)` ran are the only ones that survived more than a few seconds.
  That is correlation across a handful of runs, not a measurement, and it is why the
  call is back in the blob.

## Building

Half of this is a PS5 payload and half is x86-64 freestanding shellcode, and they
cannot share a compiler.

```sh
brew install x86_64-elf-gcc
export PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
export LLVM_CONFIG=$(brew --prefix llvm@18)/bin/llvm-config
make
```

That builds the three shellcode blobs and then the payload, in that order, passing
each subdirectory the toolchain it needs. Result: `bin/ps5-linux-1360.elf`.

If the `x86_64-elf-*` tools are named differently, override them:
`make SC_CC=x86_64-elf-gcc-14`. `SC_LD` and `SC_OBJCOPY` work the same way.

`stubinc/` exists because `x86_64-elf-gcc` ships `stdint.h` as a wrapper around a
newlib that is not installed; it holds the three minimal headers the shellcode
needs. Do not pass `CFLAGS=` to `shellcode/hv` or `shellcode/break_hv` - they set
the cave addresses there themselves and an override drops them. And set
`LLVM_CONFIG`, not `LLVM_BINDIR`: the SDK's clang wrapper reads the former, and
without it every compile fails in a way that looks like a missing toolchain.

## Running it

You need a USB drive with the [ps5-linux
image](https://github.com/ps5-linux/ps5-linux-image/releases) on it - a disk image
with a FAT32 boot partition and an ext4 root, not an ISO. `bzImage` and
`initrd.img` go in `/data/` on the console or in `PS5/Linux/` on the FAT32
partition; `cmdline.txt` and `vram.txt` are optional.

On the console:

1. Settings → System → Power Saving → Features in Rest Mode → **Supply Power to USB
   Ports = Always**
2. Settings → HDMI → **Enable HDMI Device Link = Off**
3. Run the jailbreak through to `elfldr`
4. `PS5_IP=<console> ./scripts/send.sh`
5. The payload arms the hook and enters rest mode itself. Wait for the orange light
   to stop blinking, then wake the console **with the power button** - waking it
   from the controller does not go down the resume path the hook is waiting on.

## How it works

The hook is Byepervisor's: a DR7 hardware execute breakpoint on `khv_startup_mp`,
whose `#DB` gate is redirected to `add rsp,0x28; ret` to skip the interrupt frame
and `ret` into a ROP chain on the IST-6 stack. Three fixes were needed before it
would fire at all, and each was the difference between firing and not:

- **`pin_to_core` must use `1 << (15 - n)`.** The console inverts core numbering,
  so the intuitive `1 << n` delivers the `#DB` on a core whose IST6 is zero and the
  pivot pops unrelated memory.
- **The direct map must come from `kdldmap(0)`**, not from `pm_pml4 - pm_cr3`. On
  13.60 the `pm_pml4` field of the `flat_pmap` overlay is wrong, so every
  `pa_to_dmap()` write landed outside the cave.
- **RDX carries CR3 into `khv_startup_mp`** and has to be set alongside RSI.

Nothing is loaded before the suspend: with the images resident the console powers
off after the wake whatever form they take. So the hook is armed empty and
`stage_hv_boot()` streams `/data/` into the cave at physical 4 GiB after the resume,
16 KB at a time, then reads it back and compares it with the files at the head, the
middle and the tail. The AP payload is `break_hv`, which clears `NP_ENABLE` on all
16 VMCBs and returns to the guest - an AP that does not return leaves the S3 resume
unfinished and the console powers off about five seconds after the wake.

All 31 offsets the escape uses are verified against this console's own kernel and
hypervisor dumps, by signature where the target carries one and by reading the code
at the address where not. `VMSPACE_VM_PMAP` is `0x2E8` here rather than the `0x1D8`
that two public tables carry for 13.60; the CR3 it produces is a valid physical
address and the other is not, which is why this one is kept.

## Credits

The escape is **Byepervisor**'s kernel hook and the Linux boot is
**ps5-linux-loader**'s shellcode. Both are used under their own licences; what this
repository adds is the port to 13.60.

- **[PS5Dev/Byepervisor-Reborn](https://github.com/PS5Dev/Byepervisor-Reborn)** —
  the kernel hook, the PTE walkers, `kdlsym`, `break_hv`, `pin_to_core`, and every
  `KERNEL_SYM_*` and gadget in `off_1360`.
- **[NotSoTypicalGamer/HV-Bypass-13.60](https://github.com/NotSoTypicalGamer/HV-Bypass-13.60)**
  — the working 13.60 payload this was built against.
- **[ps5-linux/ps5-linux-loader](https://github.com/ps5-linux/ps5-linux-loader)** —
  the Linux boot path, and
  **[ps5-linux-image](https://github.com/ps5-linux/ps5-linux-image)** for the image.
- **[EchoStretch/kstuff](https://github.com/EchoStretch/kstuff-lite)** — the 13.60
  table used as an anchor while deriving values.
- **[john-tornblom](https://github.com/john-tornblom)** — the
  [PS5 payload SDK](https://github.com/ps5-payload-dev/sdk), without which nothing
  here builds or runs.
- **theflow0**, who is also **TheOfficialFloW**, for the S3-resume `startup_mp`
  AP-launch bug and, with **c0w**, the boot path above; **Sonic-Iso** for the
  `startup_mp` write-up and the Route A recipe, **flatz** and **cragson** for the
  original hypervisor exploit, **cedsaill3** for the `sysent` hook and
  `WRMSR(APICBASE)`, **sleirsgoevy** for single-step kernel text recovery,
  **Gezine** for the mast1c0re / Luac0re entrypoint, and **the Relapse team** for
  the kernel R/W this jailbreak family builds on.

## Licence

GPL-3.0, see `LICENSE`. The boot path and shellcode are GPL-3.0 from
`ps5-linux-loader` and keep their original authorship; `source/byepervisor/` and
`include/byepervisor/` are AGPL-3.0-or-later from Byepervisor-Reborn; the offset
table is built on kstuff's. The attribution above is a condition of those licences,
not a courtesy.
