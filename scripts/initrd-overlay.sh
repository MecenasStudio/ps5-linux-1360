#!/usr/bin/env bash
#
# Append an overlay segment to an initrd without recompressing it.
#
# The initramfs is a concatenation of archives and a file in a later archive
# replaces one from an earlier archive, so a modified /init can be added without
# touching the original image at all. That matters: recompressing the whole thing
# with a different zstd setting made a smaller file than the original and the
# kernel refused the image outright, which cost a long detour - every test built
# on that image was measuring the repack rather than the thing under test.
#
# The padding is not cosmetic either. The kernel's cpio parser wants the header
# 4-byte aligned, and the original image ends at 28095979 bytes, which is 3 mod 4.
# Appending straight onto the end put the new header at an unaligned offset and
# the kernel rejected it just as hard.
#
# usage: initrd-overlay.sh <original-initrd> <file-to-overlay> <output>
#   e.g. initrd-overlay.sh initrd.img init /tmp/initrd-overlay.img
#
# <file-to-overlay> is placed at the root of the initramfs under its own name.

set -euo pipefail

orig="${1:?usage: $0 <original-initrd> <file> <output>}"
file="${2:?usage: $0 <original-initrd> <file> <output>}"
out="${3:?usage: $0 <original-initrd> <file> <output>}"

[ -f "$orig" ] || { echo "no such file: $orig" >&2; exit 1; }
[ -f "$file" ] || { echo "no such file: $file" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

rm -rf "$work/tree" && mkdir -p "$work/tree"
cp "$file" "$work/tree/$(basename "$file")"
# The archive is written outside the directory being packed: cpio refuses to add
# an archive to itself, and a redirect into the tree creates the file before find
# walks it.
( cd "$work/tree" && find . | cpio -o -H newc --quiet ) > "$work/overlay.cpio"

size=$(stat -f%z "$orig" 2>/dev/null || stat -c%s "$orig")
pad=$(( (512 - size % 512) % 512 ))

cat "$orig" > "$out"
[ "$pad" -gt 0 ] && dd if=/dev/zero bs=1 count="$pad" >> "$out" 2>/dev/null
cat "$work/overlay.cpio" >> "$out"

echo "original : $size B (mod 512 = $((size % 512)))"
echo "padding  : $pad B"
echo "overlay  : $(stat -f%z "$work/overlay.cpio") B"
echo "output   : $(stat -f%z "$out") B"
echo "segment starts at $((size + pad)) (mod 4 = $(( (size + pad) % 4 )))"
