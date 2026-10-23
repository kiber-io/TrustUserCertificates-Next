#include "protocol.hpp"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>

static void hook_policy_check() {
    char directory[PATH_MAX];
    const char *temporary = getenv("TMPDIR");
    int length = snprintf(directory, sizeof(directory), "%s/trustusercerts-hooks-XXXXXX", temporary ? temporary : "/tmp");
    assert(length > 0 && length < static_cast<int>(sizeof(directory)) && mkdtemp(directory));
    int snapshot = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert(snapshot >= 0);
    uint8_t flags = 255;
    assert(tuc::read_hook_flags(snapshot, flags) && flags == 0);
    int file = openat(snapshot, "hooks", O_CREAT | O_RDWR | O_EXCL | O_CLOEXEC, 0600);
    assert(file >= 0);
    assert(!tuc::read_hook_flags(snapshot, flags) && flags == 0);
    for (uint8_t value = 0; value <= 8; ++value) {
        assert(pwrite(file, &value, 1, 0) == 1);
        bool valid = value >= 1 && value <= 7;
        assert(tuc::read_hook_flags(snapshot, flags) == valid);
        assert(flags == (valid ? value : 0));
    }
    const uint8_t extra[] = {1, 2};
    assert(pwrite(file, extra, sizeof(extra), 0) == sizeof(extra));
    assert(!tuc::read_hook_flags(snapshot, flags) && flags == 0);
    close(file);
    assert(unlinkat(snapshot, "hooks", 0) == 0);
    assert(mkdirat(snapshot, "hooks", 0700) == 0);
    assert(!tuc::read_hook_flags(snapshot, flags) && flags == 0);
    assert(unlinkat(snapshot, "hooks", AT_REMOVEDIR) == 0);
    assert(mkfifoat(snapshot, "hooks", 0600) == 0);
    assert(!tuc::read_hook_flags(snapshot, flags) && flags == 0);
    assert(unlinkat(snapshot, "hooks", 0) == 0);
    file = openat(snapshot, "policy", O_CREAT | O_WRONLY | O_EXCL | O_CLOEXEC, 0600);
    assert(file >= 0 && write(file, extra, 1) == 1);
    close(file);
    assert(symlinkat("policy", snapshot, "hooks") == 0);
    assert(!tuc::read_hook_flags(snapshot, flags) && flags == 0);
    assert(unlinkat(snapshot, "hooks", 0) == 0 && unlinkat(snapshot, "policy", 0) == 0);
    for (unsigned value = 0; value <= 255; ++value)
        assert(tuc::selected_response(value) == ((value & 1) && value <= 15));
    for (uint8_t requested = 0; requested <= 8; ++requested) {
        for (uint32_t active = 0; active <= 15; ++active) {
            tuc::HookReport report{tuc::kMagic, requested, active};
            assert(tuc::valid_hook_report(report, requested) ==
                (requested >= 1 && requested <= 7 && (active & ~static_cast<uint32_t>(requested)) == 0));
            report.magic = 0;
            assert(!tuc::valid_hook_report(report, requested));
            report.magic = tuc::kMagic;
            ++report.requested;
            assert(!tuc::valid_hook_report(report, requested));
        }
    }
    close(snapshot);
    assert(rmdir(directory) == 0);
}

static void snapshot_selection_check() {
    char directory[PATH_MAX];
    const char *temporary = getenv("TMPDIR");
    int length = snprintf(directory, sizeof(directory), "%s/trustusercerts-snapshot-XXXXXX", temporary ? temporary : "/tmp");
    assert(length > 0 && length < static_cast<int>(sizeof(directory)));
    assert(mkdtemp(directory));
    int snapshot = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert(snapshot >= 0);
    assert(mkdirat(snapshot, "apps", 0700) == 0);
    assert(mkdirat(snapshot, "apps/0", 0700) == 0);
    assert(mkdirat(snapshot, "apps/0/ru.example.app", 0700) == 0);
    assert(mkdirat(snapshot, "apps/10", 0700) == 0);
    assert(mkdirat(snapshot, "apps/10/ru.example.app", 0700) == 0);
    assert(mkdirat(snapshot, "global", 0700) == 0);
    assert(tuc::open_user_snapshot(snapshot, 10001) < 0 && errno == ENOENT);
    assert(mkdirat(snapshot, "user", 0700) == 0);
    assert(mkdirat(snapshot, "user/0", 0700) == 0);
    assert(mkdirat(snapshot, "user/10", 0700) == 0);
    struct UserStoreCase { uint32_t uid; const char *directory; };
    const UserStoreCase users[] = {{10001, "user/0"}, {1010001, "user/10"}};
    for (const auto &user : users) {
        int selected_user = tuc::open_user_snapshot(snapshot, user.uid);
        struct stat user_actual{}, user_expected{};
        assert(selected_user >= 0 && fstat(selected_user, &user_actual) == 0);
        assert(fstatat(snapshot, user.directory, &user_expected, 0) == 0);
        assert(user_actual.st_dev == user_expected.st_dev && user_actual.st_ino == user_expected.st_ino);
        close(selected_user);
    }
    assert(tuc::open_user_snapshot(snapshot, 110001) < 0 && errno == ENOENT);
    assert(tuc::open_user_snapshot(snapshot, 99001) < 0 && errno == EINVAL);
    assert(symlinkat("0", snapshot, "user/1") == 0);
    assert(tuc::open_user_snapshot(snapshot, 110001) < 0);
    assert(unlinkat(snapshot, "user/1", 0) == 0);
    int config_fd = openat(snapshot, "config", O_WRONLY | O_CREAT | O_EXCL, 0600);
    const char record[] = "10001 ru.example.app\n1010001 ru.example.app\n";
    assert(config_fd >= 0 && write(config_fd, record, sizeof(record) - 1) == sizeof(record) - 1);
    close(config_fd);
    tuc::Request request;
    request.uid = 10001;
    assert(tuc::package_from_path("/data/user/0/ru.example.app", request.uid, request.package));
    int selected = tuc::open_effective_snapshot(snapshot, request);
    struct stat actual{}, expected{};
    assert(selected >= 0 && fstat(selected, &actual) == 0);
    assert(fstatat(snapshot, "apps/0/ru.example.app", &expected, 0) == 0 && actual.st_ino == expected.st_ino);
    close(selected);
    request.uid = 10002;
    assert(tuc::open_effective_snapshot(snapshot, request) < 0 && errno == ENOENT);
    int marker = openat(snapshot, "global/enabled", O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(marker >= 0);
    close(marker);
    // An unselected UID gets only the enabled global store; an explicit package keeps its union.
    selected = tuc::open_effective_snapshot(snapshot, request);
    assert(selected >= 0 && fstat(selected, &actual) == 0);
    assert(fstatat(snapshot, "global", &expected, 0) == 0 && actual.st_ino == expected.st_ino);
    close(selected);
    request.uid = 1010001;
    selected = tuc::open_effective_snapshot(snapshot, request);
    assert(selected >= 0 && fstat(selected, &actual) == 0);
    assert(fstatat(snapshot, "apps/10/ru.example.app", &expected, 0) == 0 && actual.st_ino == expected.st_ino);
    close(selected);
    request.uid = 110001;
    selected = tuc::open_effective_snapshot(snapshot, request);
    assert(selected >= 0 && fstat(selected, &actual) == 0);
    assert(fstatat(snapshot, "global", &expected, 0) == 0 && actual.st_ino == expected.st_ino);
    close(selected);
    request.uid = 1010001;
    assert(unlinkat(snapshot, "apps/10/ru.example.app", AT_REMOVEDIR) == 0);
    assert(unlinkat(snapshot, "apps/10", AT_REMOVEDIR) == 0);
    assert(symlinkat("0", snapshot, "apps/10") == 0);
    assert(tuc::open_effective_snapshot(snapshot, request) < 0);
    assert(unlinkat(snapshot, "apps/10", 0) == 0);
    assert(tuc::open_effective_snapshot(snapshot, request) < 0 && errno == ENODATA);
    request.uid = 10001;
    selected = tuc::open_effective_snapshot(snapshot, request);
    assert(selected >= 0 && fstat(selected, &actual) == 0);
    assert(fstatat(snapshot, "apps/0/ru.example.app", &expected, 0) == 0 && actual.st_ino == expected.st_ino);
    close(selected);
    assert(unlinkat(snapshot, "apps/0/ru.example.app", AT_REMOVEDIR) == 0);
    assert(tuc::open_effective_snapshot(snapshot, request) < 0 && errno == ENODATA);
    request.uid = 99001;
    assert(tuc::open_effective_snapshot(snapshot, request) < 0 && errno == EINVAL);
    request.uid = 10002;
    assert(unlinkat(snapshot, "global/enabled", 0) == 0);
    assert(symlinkat("../config", snapshot, "global/enabled") == 0);
    assert(tuc::open_effective_snapshot(snapshot, request) < 0 && errno == EINVAL);
    assert(unlinkat(snapshot, "global/enabled", 0) == 0);
    config_fd = openat(snapshot, "config", O_WRONLY | O_TRUNC);
    assert(config_fd >= 0);
    close(config_fd);
    marker = openat(snapshot, "global/enabled", O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(marker >= 0);
    close(marker);
    selected = tuc::open_effective_snapshot(snapshot, request);
    assert(selected >= 0);
    close(selected);
    assert(unlinkat(snapshot, "global/enabled", 0) == 0);
    assert(unlinkat(snapshot, "config", 0) == 0);
    assert(unlinkat(snapshot, "global", AT_REMOVEDIR) == 0);
    assert(unlinkat(snapshot, "user/0", AT_REMOVEDIR) == 0);
    assert(unlinkat(snapshot, "user/10", AT_REMOVEDIR) == 0);
    assert(unlinkat(snapshot, "user", AT_REMOVEDIR) == 0);
    assert(symlinkat("apps", snapshot, "user") == 0);
    assert(tuc::open_user_snapshot(snapshot, 10001) < 0);
    assert(unlinkat(snapshot, "user", 0) == 0);
    assert(unlinkat(snapshot, "apps/0", AT_REMOVEDIR) == 0);
    assert(unlinkat(snapshot, "apps", AT_REMOVEDIR) == 0);
    close(snapshot);
    assert(rmdir(directory) == 0);
}

int main(int argc, char **argv) {
    using namespace tuc;
    if (argc == 2 && !strcmp(argv[1], "--zygote-name-check")) {
        assert(prctl(PR_SET_NAME, "main", 0, 0, 0) == 0);
        assert(zygote_process(getpid()));
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "--zygote-pid")) {
        int pid = 0;
        assert(sscanf(argv[2], "%d", &pid) == 1 && pid > 1);
        assert(zygote_process(pid));
        return 0;
    }
    assert(!zygote_process(getpid()));
    Request request;
    request.uid = 10001;
    assert(package_from_path("/data/user/0/ru.example.app", request.uid, request.package));
    assert(!package_from_path("/data/user/10/ru.example.app", request.uid, request.package));
    assert(!package_from_path("/data/user/0/ru.example.app/../other", request.uid, request.package));
    assert(package_from_path("/data/data/ru.example.app", request.uid, request.package));
    assert(package_from_path("/data/user_de/0/ru.example.app", request.uid, request.package));
    request.uid = 1010001;
    assert(package_from_path("/data/user/10/ru.example.app", request.uid, request.package));
    assert(package_from_path("/data/user_de/10/ru.example.app", request.uid, request.package));
    assert(!package_from_path("/data/user/0/ru.example.app", request.uid, request.package));
    assert(!package_from_path("/data/user_de/0/ru.example.app", request.uid, request.package));
    assert(!package_from_path("/data/data/ru.example.app", request.uid, request.package));
    assert(!package_from_path("/data/user/010/ru.example.app", request.uid, request.package));
    assert(!package_from_path("/data/user/-10/ru.example.app", request.uid, request.package));
    assert(!package_from_path("/data/user/42949672960/ru.example.app", request.uid, request.package));
    assert(!package_from_path("/data/user_de/10/ru.example.app/other", request.uid, request.package));
    request.uid = 10001;
    assert(!package_name("ru..example"));
    assert(!package_name(".ru.example"));
    assert(!package_name("ru.example/"));
    assert(!regular_uid(9999) && !regular_uid(20000) && !regular_uid(99001) && !regular_uid(1099001));
    assert(regular_uid(110001) && regular_uid(1010000) && regular_uid(1019999));
    assert(!regular_uid(1001000) && !regular_uid(1020000) && !regular_uid(1090001));
    FILE *config = tmpfile();
    assert(config);
    fputs("10001 ru.example.app\n10002 ru.example.other\n", config);
    rewind(config);
    assert(allowed(config, request));
    request.uid = 10002;
    rewind(config);
    assert(!allowed(config, request));
    request.uid = 10001;
    request.magic = 0;
    rewind(config);
    assert(!allowed(config, request));
    fclose(config);
    snapshot_selection_check();
    hook_policy_check();
}
