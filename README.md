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
escape the hypervisor                    works
stage the Linux images in the cave       works, verified byte for byte
start the kernel                         works
initramfs runs                           works
wait for the root filesystem             fails - not found, platform powers off
```

**The remaining fault is the root filesystem.** The command line asks for
`root=LABEL=ubuntu2604`, and the initramfs spends about ninety seconds looking for
it before the platform cuts the power. Either the stick does not carry that label,
or its partitions are not in the order the image expects - this one has the Linux
filesystem on `sda1` and the EFI partition on `sda2`. If the root mounts, the boot
stops timing out and the console stays up.

**The screen stays black even that far in.** The reference boot path makes four
display calls before starting the kernel and this path has to make them itself. Two
are in place: the VBIOS copied to `0xC0000` and `mp3_initialize(0)`, which is what
took the console from dying after five seconds to surviving ninety. The other two
need `FUN_TRANSMITTER_CONTROL` (the DP link) and `FUN_MP3_INVOKE` (HDCP and output),
and neither offset is known for 13.60. Until the DP link is there, `console=tty0`
has nowhere to draw.

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
