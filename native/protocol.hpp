#pragma once

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace tuc {
constexpr uint32_t kMagic = 0x54554331;
struct Request {
    uint32_t magic = kMagic;
    uint32_t uid = 0;
    char package[256] = {};
};

inline bool regular_uid(uint32_t uid) {
    uint32_t app_id = uid % 100000;
    return app_id >= 10000 && app_id <= 19999;
}

inline bool selected_response(uint8_t value) { return (value & 1) && value <= 15; }

struct HookReport { uint32_t magic = kMagic; uint32_t requested = 0; uint32_t active = 0; };
inline bool valid_hook_report(const HookReport &report, uint8_t requested) {
    return requested >= 1 && requested <= 7 && report.magic == kMagic &&
        report.requested == requested && (report.active & ~static_cast<uint32_t>(requested)) == 0;
}

inline bool read_hook_flags(int snapshot, uint8_t &flags) {
    flags = 0;
    int fd = openat(snapshot, "hooks", O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return errno == ENOENT;
    struct stat file{};
    bool ok = fstat(fd, &file) == 0;
    if (ok && (!S_ISREG(file.st_mode) || file.st_size != 1)) { errno = EINVAL; ok = false; }
    uint8_t data[2] = {};
    ssize_t count = -1;
    if (ok) {
        do { count = read(fd, data, sizeof(data)); } while (count < 0 && errno == EINTR);
        if (count >= 0 && (count != 1 || data[0] < 1 || data[0] > 7)) errno = EINVAL;
        ok = count == 1 && data[0] >= 1 && data[0] <= 7;
    }
    int error = errno;
    close(fd);
    errno = error;
    if (ok) flags = data[0];
    return ok;
}

inline bool zygote_process(pid_t pid) {
    char path[64], name[32] = {};
    // Android can leave comm as "main"; argv[0] identifies the Zygote process.
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    FILE *command = fopen(path, "re");
    if (!command) return false;
    size_t n = fread(name, 1, sizeof(name) - 1, command);
    fclose(command);
    return n > 0 && (!strcmp(name, "zygote") || !strcmp(name, "zygote64"));
}

inline bool package_name(const char *name) {
    size_t n = strnlen(name, 256);
    if (!n || n == 256 || name[0] == '.' || name[n - 1] == '.') return false;
    bool dot = false;
    for (size_t i = 0; i < n; ++i) {
        char c = name[i];
        if (c == '.') {
            if (i && name[i - 1] == '.') return false;
            dot = true;
        } else if (!(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') &&
                   !(c >= '0' && c <= '9') && c != '_') return false;
    }
    return dot;
}

inline bool package_from_path(const char *path, uint32_t uid, char (&output)[256]) {
    if (!regular_uid(uid)) return false;
    uint32_t user = uid / 100000;
    char credential_path[40], device_path[40];
    snprintf(credential_path, sizeof(credential_path), "/data/user/%u/", user);
    snprintf(device_path, sizeof(device_path), "/data/user_de/%u/", user);
    const char *package = nullptr;
    if (!strncmp(path, credential_path, strlen(credential_path))) package = path + strlen(credential_path);
    else if (!strncmp(path, device_path, strlen(device_path))) package = path + strlen(device_path);
    else if (user == 0 && !strncmp(path, "/data/data/", 11)) package = path + 11;
    if (!package || !package_name(package)) return false;
    memcpy(output, package, strlen(package) + 1);
    return true;
}

inline bool allowed(FILE *config, const Request &request) {
    if (request.magic != kMagic || !regular_uid(request.uid) || !package_name(request.package)) return false;
    char line[300], package[256], extra;
    unsigned uid;
    size_t lines = 0;
    while (lines++ < 10000 && fgets(line, sizeof(line), config)) {
        if (!strchr(line, '\n') && !feof(config)) return false;
        if (sscanf(line, "%u %255s %c", &uid, package, &extra) == 2 &&
            uid == request.uid && !strcmp(package, request.package)) return true;
    }
    return false;
}

inline int open_effective_snapshot(int snapshot, const Request &request) {
    if (request.magic != kMagic || !regular_uid(request.uid) || !package_name(request.package)) {
        errno = EINVAL;
        return -1;
    }
    int config_fd = openat(snapshot, "config", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (config_fd < 0) return -1;
    FILE *config = fdopen(config_fd, "r");
    if (!config) { int error = errno; close(config_fd); errno = error; return -1; }
    bool individual = allowed(config, request);
    bool failed = ferror(config);
    int config_error = errno;
    fclose(config);
    if (failed) { errno = config_error; return -1; }
    if (individual) {
        int apps = openat(snapshot, "apps", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (apps < 0) { if (errno == ENOENT) errno = ENODATA; return -1; }
        char user[16];
        snprintf(user, sizeof(user), "%u", request.uid / 100000);
        int profile = openat(apps, user, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        int error = errno;
        close(apps);
        if (profile < 0) { errno = error == ENOENT ? ENODATA : error; return -1; }
        int selected = openat(profile, request.package, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        error = errno;
        close(profile);
        errno = selected < 0 && error == ENOENT ? ENODATA : error;
        return selected;
    }
    int global = openat(snapshot, "global", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (global < 0) return -1;
    struct stat enabled{};
    int marker_status = fstatat(global, "enabled", &enabled, AT_SYMLINK_NOFOLLOW);
    if (marker_status != 0 || !S_ISREG(enabled.st_mode) || enabled.st_size != 0) {
        int error = marker_status != 0 ? errno : EINVAL;
        close(global);
        errno = error;
        return -1;
    }
    return global;
}

inline int open_user_snapshot(int snapshot, uint32_t uid) {
    if (!regular_uid(uid)) { errno = EINVAL; return -1; }
    int users = openat(snapshot, "user", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (users < 0) return -1;
    char user[16];
    snprintf(user, sizeof(user), "%u", uid / 100000);
    int selected = openat(users, user, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int error = errno;
    close(users);
    errno = error;
    return selected;
}
} // namespace tuc
