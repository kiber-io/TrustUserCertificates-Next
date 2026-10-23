#include "PlatformUtil/ProcessRuntimeUtility.h"

#include <elf.h>
#include <dlfcn.h>
#include <link.h>
#include <sys/mman.h>

#include <string>
#include <string.h>

#include <vector>
#include <algorithm>

#define LINE_MAX 2048

// ================================================================
// GetProcessMemoryLayout

static bool memory_region_comparator(MemRange a, MemRange b) {
  return (a.start < b.start);
}

tinystl::vector<MemRegion> regions;
const tinystl::vector<MemRegion> &ProcessRuntimeUtility::GetProcessMemoryLayout() {
  regions.clear();

  FILE *fp = fopen("/proc/self/maps", "r");
  if (fp == nullptr)
    return regions;

  while (!feof(fp)) {
    char line_buffer[LINE_MAX + 1];
    fgets(line_buffer, LINE_MAX, fp);

    // ignore the rest of characters
    if (strlen(line_buffer) == LINE_MAX && line_buffer[LINE_MAX] != '\n') {
      // Entry not describing executable data. Skip to end of line to set up
      // reading the next entry.
      int c;
      do {
        c = getc(fp);
      } while ((c != EOF) && (c != '\n'));
      if (c == EOF)
        break;
    }

    addr_t region_start, region_end;
    addr_t region_offset;
    char permissions[5] = {'\0'}; // Ensure NUL-terminated string.
    uint8_t dev_major = 0;
    uint8_t dev_minor = 0;
    long inode = 0;
    int path_index = 0;

    // Sample format from man 5 proc:
    //
    // address           perms offset  dev   inode   pathname
    // 08048000-08056000 r-xp 00000000 03:0c 64593   /usr/sbin/gpm
    //
    // The final %n term captures the offset in the input string, which is used
    // to determine the path name. It *does not* increment the return value.
    // Refer to man 3 sscanf for details.
    if (sscanf(line_buffer,
               "%" PRIxPTR "-%" PRIxPTR " %4c "
               "%" PRIxPTR " %hhx:%hhx %ld %n",
               &region_start, &region_end, permissions, &region_offset, &dev_major, &dev_minor, &inode,
               &path_index) < 7) {
      ERROR_LOG("/proc/self/maps parse failed!");
      fclose(fp);
      return regions;
    }

    MemoryPermission permission;
    if (permissions[0] == 'r' && permissions[1] == 'w') {
      permission = MemoryPermission::kReadWrite;
    } else if (permissions[0] == 'r' && permissions[2] == 'x') {
      permission = MemoryPermission::kReadExecute;
    } else if (permissions[0] == 'r' && permissions[1] == 'w' && permissions[2] == 'x') {
      permission = MemoryPermission::kReadWriteExecute;
    } else {
      permission = MemoryPermission::kNoAccess;
    }

#if 0
      DEBUG_LOG("%p --- %p", region_start, region_end);
#endif

    MemRegion region = MemRegion(region_start, region_end - region_start, permission);
    regions.push_back(region);
  }
  std::sort(regions.begin(), regions.end(), memory_region_comparator);

  fclose(fp);
  return regions;
}

// ================================================================
// GetProcessModuleMap

// TrustUserCertificates: enumerate loader-owned ELF images. Reading arbitrary
// /proc/self/maps entries as ELF headers can SIGBUS on file mappings beyond EOF.
const tinystl::vector<RuntimeModule> &ProcessRuntimeUtility::GetProcessModuleMap() {
  static tinystl::vector<RuntimeModule> modules;
  modules.clear();
  dl_iterate_phdr([](dl_phdr_info *info, size_t, void *data) {
    if (!info->dlpi_name || info->dlpi_name[0] != '/') return 0;
    RuntimeModule module{};
    if (strlen(info->dlpi_name) >= sizeof(module.path)) return 0;
    strcpy(module.path, info->dlpi_name);
    for (size_t i = 0; i < info->dlpi_phnum; ++i) {
      if (info->dlpi_phdr[i].p_type == PT_LOAD) {
        module.load_address = reinterpret_cast<void *>(info->dlpi_addr +
            info->dlpi_phdr[i].p_vaddr - info->dlpi_phdr[i].p_offset);
        static_cast<tinystl::vector<RuntimeModule> *>(data)->push_back(module);
        break;
      }
    }
    return 0;
  }, &modules);
  return modules;
}

RuntimeModule ProcessRuntimeUtility::GetProcessModule(const char *name) {
  auto modules = GetProcessModuleMap();
  for (auto module : modules) {
    if (strstr(module.path, name) != 0) {
      return module;
    }
  }
  return RuntimeModule{0};
}