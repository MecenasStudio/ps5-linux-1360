#include "loader.h"
#include "config.h"
#include "firmware.h"
#include "linux.h"
#include "utils.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/mman.h>
#include <sys/stat.h>

const char *file_paths[] = {
    /* Internal storage first.
     *
     * The USB stack does not come back after S3 on this console, and touching a
     * stick before the suspend costs the resume: measured on 13.60, loading the
     * images from /mnt/usb0 before sleeping makes the console power off a few
     * seconds after the wake, while the same payload with no images loaded comes
     * back with NP_ENABLE cleared. /data/ is on the internal drive, is where this
     * payload already writes its log, and involves no USB at all.
     *
     * Put bzImage, initrd.img, vram.txt and cmdline.txt in /data/ to use it. */
    "/data/",
    "/mnt/usb0/",           "/mnt/usb1/",           "/mnt/usb2/",
    "/mnt/usb3/",           "/mnt/usb0/PS5/Linux/", "/mnt/usb1/PS5/Linux/",
    "/mnt/usb2/PS5/Linux/", "/mnt/usb3/PS5/Linux/",
};

long find_and_get_size_of_file(const char *filename, char *found_path);
int find_and_read_file(const char *filename, void *buf, size_t bufsize);

static const char *get_overridden_filename(const char *filename) {
  static int state = 0;
  static char *overrides_start = nullptr;
  static char *overrides_end = nullptr;

  if (state == 0) {
    state = 1;
    char found_path[256];
    ssize_t size = find_and_get_size_of_file("path-override.txt", found_path);
    if (size > 0) {
      overrides_start = malloc(size + 1);
      overrides_end = overrides_start + size + 1;
      if (read_file(found_path, overrides_start, size) == size) {
        state = 2;
        for (char *p = overrides_start; p < overrides_end; p++)
          if (*p == '\n')
            *p = 0;
        // make sure the last string is null-terminated
        overrides_start[size] = 0;
      }
    }
  }

  // overrides not found, or unreadable, or currently looking for it
  if (state == 1)
    return filename;

  size_t needle_len = strlen(filename);
  for (const char *p = overrides_start; p < overrides_end;) {
    size_t haystack_len = strlen(p);
    if (haystack_len > needle_len && !strncmp(p, filename, needle_len) &&
        p[needle_len] == '=')
      return p + needle_len + 1;
    p += haystack_len + 1;
  }

  // haven't found an override, return original filename
  return filename;
}

long find_and_get_size_of_file(const char *filename, char *found_path) {
  char full_path[256];
  struct stat st;

  filename = get_overridden_filename(filename);
  int num_paths = sizeof(file_paths) / sizeof(file_paths[0]);

  for (int i = 0; i < num_paths; i++) {
    snprintf(full_path, sizeof(full_path), "%s%s", file_paths[i], filename);

    if (stat(full_path, &st) == 0) {
      notify("File '%s' found in '%s'\n", filename, file_paths[i]);
      strcpy(found_path, full_path);
      return st.st_size;
    }
  }

  return -1;
}

int find_and_read_file(const char *filename, void *buf, size_t bufsize) {
  char full_path[256];
  struct stat st;

  int num_paths = sizeof(file_paths) / sizeof(file_paths[0]);

  for (int i = 0; i < num_paths; i++) {
    snprintf(full_path, sizeof(full_path), "%s%s", file_paths[i], filename);

    if (stat(full_path, &st) == 0) {
      notify("File '%s' found in '%s'\n", filename, file_paths[i]);
      return read_file(full_path, buf, bufsize);
    }
  }

  return -1;
}

int read_file(const char *path, void *buf, size_t bufsize) {
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return fd;
  int r = read(fd, buf, bufsize);
  close(fd);
  return r;
}

void trim_newline(char *s) {
  while (*s != '\0') {
    if (*s == '\r' || *s == '\n') {
      *s = '\0';
      break;
    }
    s++;
  }
}

/* Read vram.txt, falling back to the compiled-in size. */
static size_t read_vram_size(void) {
  char buf[16] = {};
  if (find_and_read_file("vram.txt", buf, sizeof(buf) - 1) < 0) {
    printf("File vram.txt not found at default paths - Using static fallback\n");
    return VRAM_SIZE;
  }
  trim_newline(buf);
  size_t v = strtoull(buf, NULL, 16);
  if (v == 0) {
    printf("Seems like the configured vram value is wrong - Using static "
           "fallback\n");
    return VRAM_SIZE;
  }
  return v;
}

/* Read cmdline.txt, falling back to the compiled-in line. */
static void read_cmdline(char *out, size_t out_size) {
  out[0] = '\0';
  if (find_and_read_file("cmdline.txt", out, out_size - 1) < 0) {
    printf("File cmdline.txt not found at default paths - Using static "
           "fallback\n");
    strcpy(out, CMD_LINE);
    return;
  }
  trim_newline(out);
}

int fetch_linux(struct linux_info *info) {
  char bzimage_path[256] = {};
  char initrd_path[256] = {};

  size_t bzimage_size = find_and_get_size_of_file("bzImage", bzimage_path);
  if (bzimage_size < 0) {
    notify("File bzImage not found at default paths - Aborting\n");
    return -1;
  }

  size_t initrd_size = find_and_get_size_of_file("initrd.img", initrd_path);
  if (initrd_size < 0) {
    notify("File initrd.img not found at default paths - Aborting\n");
    return -1;
  }

  if (dump_device_firmwares(initrd_path) < 0) {
    notify(
        "Something went wrong while dumping device firmwares - Continuing\n");
  }

  size_t vram_size = read_vram_size();
  char cmdline[2048] = {};
  read_cmdline(cmdline, sizeof(cmdline));

  extern uint32_t fw;

  /* Probe only: record the paths and sizes, map nothing, read nothing.
   *
   * Every run that died had the images resident before the suspend, and every run
   * that survived had none - including the one with the execute breakpoint armed,
   * which is the reference payload's own configuration. Loading them here is what
   * stops the console coming back, whether they sit as a plain mapping, as wired
   * pages, or already written into the cave.
   *
   * Reading them after the resume is safe: bzImage was found there and the only
   * failure was the allocation, mmap(MAP_SHARED | MAP_ANONYMOUS), which this path
   * no longer uses. stage_hv_boot() streams from these paths into the cave 16 KB
   * at a time, so nothing large is ever allocated. */
  snprintf(linux_bzimage_path, sizeof(linux_bzimage_path), "%s", bzimage_path);
  snprintf(linux_initrd_path, sizeof(linux_initrd_path), "%s", initrd_path);
  linux_bzimage_len = bzimage_size;
  linux_initrd_len = initrd_size;

  info->linux_info = kernel_cave_linux_info;
  info->bzimage = kernel_cave_bzImage;
  info->bzimage_size = bzimage_size;
  info->initrd = kernel_cave_bzImage + ALIGN_UP(bzimage_size, PAGE_SIZE);
  info->initrd_size = initrd_size;
  info->vram_size = vram_size;
  info->kit_type = (int)get_kit_type();
  strcpy(info->cmdline, cmdline);

  notify("13.60: images recorded for streaming after the resume: %s (%zu B), "
         "%s (%zu B).\n",
         linux_bzimage_path, bzimage_size, linux_initrd_path, initrd_size);
  return 0;
}
