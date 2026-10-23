#include <stdint.h>
#include <sys/types.h>
#include "zygisk.hpp"
#include "protocol.hpp"

#include <errno.h>
#include <android/dlext.h>
#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/memfd.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

namespace {
constexpr char kRuntime[] = "/dev/trustusercerts";
#ifdef TUC_DIAGNOSTIC
constexpr char kSystem[] = "/dev/trustusercerts-check/system";
constexpr char kApex[] = "/dev/trustusercerts-check/apex";
constexpr char kUser[] = "/dev/trustusercerts-check/user";
#else
constexpr char kSystem[] = "/system/etc/security/cacerts";
constexpr char kApex[] = "/apex/com.android.conscrypt/cacerts";
#endif

enum Phase : uint32_t {
    Applied, ExemptFd, Unshare, ReadyReceive, ReadyProtocol, FinalIdentity,
    NamespaceOpen, NamespaceStat, NamespaceShared, SystemSource, ApexSource,
    WorkerPipe, WorkerFork, WorkerTimeout, WorkerReply, NamespaceEnter,
    PropagationPrivate, ApexTarget, SystemTarget, SystemBind, ApexBind,
    SystemReadonly, ApexReadonly, AppSnapshot, PipeDescriptors, AckMap,
    UserSource, UserTarget, UserBind, UserReadonly,
    HookPolicy,
};
struct Result { uint32_t phase; int32_t error; };
struct Ready { uint32_t phase; int32_t error; };

const char *phase_name(uint32_t phase) {
    static const char *names[] = {"applied", "pre-exempt-fd", "pre-unshare", "post-ready-receive",
        "post-ready-protocol", "post-identity", "namespace-open", "namespace-stat", "namespace-shared",
        "system-source", "apex-source", "worker-pipe", "worker-fork", "worker-timeout", "worker-reply",
        "namespace-setns", "propagation-private", "apex-target", "system-target", "system-bind",
        "apex-bind", "system-readonly", "apex-readonly", "snapshot-select", "pipe-descriptors", "ack-map",
        "user-source", "user-target", "user-bind", "user-readonly", "hook-policy"};
    return phase < sizeof(names) / sizeof(names[0]) ? names[phase] : "unknown";
}

void log_result(pid_t pid, const char *package, const char *result);

void log_phase(pid_t pid, const char *package, Result result, const char *detail = "") {
    char message[320];
    snprintf(message, sizeof(message), "phase=%s errno=%d (%s) %s", phase_name(result.phase),
             result.error, result.error ? strerror(result.error) : "none", detail);
    log_result(pid, package, message);
}

void log_result(pid_t pid, const char *package, const char *result) {
    char line[512];
    int n = snprintf(line, sizeof(line), "[zygisk] pid=%d package=%s %s\n", pid, package, result);
    int fd = open("/data/adb/trustusercerts/module.log", O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
    if (fd >= 0) {
        if (n > 0 && n < static_cast<int>(sizeof(line))) (void)write(fd, line, n);
        close(fd);
    }
}

bool transfer(int fd, void *buffer, size_t length, bool writing) {
    auto *p = static_cast<char *>(buffer);
    while (length) {
        ssize_t n = writing ? send(fd, p, length, MSG_NOSIGNAL) : recv(fd, p, length, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { if (n == 0) errno = ECONNRESET; return false; }
        p += n;
        length -= n;
    }
    return true;
}

void timeout(int fd) {
    timeval limit{3, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof(limit));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof(limit));
}


constexpr size_t kAckSize = 4096;

int create_ack(uint32_t *&mapping) {
    int fd = syscall(__NR_memfd_create, "trustusercerts-ack", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0) return -1;
    if (ftruncate(fd, kAckSize) != 0 || fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL) != 0) {
        int error = errno; close(fd); errno = error; return -1;
    }
    void *memory = mmap(nullptr, kAckSize, PROT_READ, MAP_SHARED, fd, 0);
    if (memory == MAP_FAILED) { int error = errno; close(fd); errno = error; return -1; }
    mapping = static_cast<uint32_t *>(memory);
    return fd;
}

uint32_t wait_ack(const uint32_t *mapping) {
    timespec started{};
    if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) return 0;
    int64_t deadline = started.tv_sec * 1000000000LL + started.tv_nsec + 3000000000LL;
    for (;;) {
        uint32_t result = __atomic_load_n(mapping, __ATOMIC_ACQUIRE);
        if (result == 1 || result == 2) return result;
        if (result != 0) { errno = EPROTO; return 0; }
        timespec current{};
        if (clock_gettime(CLOCK_MONOTONIC, &current) != 0) return 0;
        if (current.tv_sec * 1000000000LL + current.tv_nsec >= deadline) { errno = ETIMEDOUT; return 0; }
        timespec pause{0, 1000000};
        (void)nanosleep(&pause, nullptr);
    }
}

bool send_request(int fd, tuc::Request &request, int ready_read, int acknowledgement) {
    iovec data{&request, sizeof(request)};
    alignas(cmsghdr) char control[CMSG_SPACE(2 * sizeof(int))] = {};
    msghdr message{};
    message.msg_iov = &data;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    cmsghdr *c = CMSG_FIRSTHDR(&message);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(2 * sizeof(int));
    int descriptors[2] = {ready_read, acknowledgement};
    memcpy(CMSG_DATA(c), descriptors, sizeof(descriptors));
    ssize_t sent;
    do { sent = sendmsg(fd, &message, MSG_NOSIGNAL); } while (sent < 0 && errno == EINTR);
    return sent > 0 && transfer(fd, reinterpret_cast<char *>(&request) + sent, sizeof(request) - sent, true);
}

bool receive_request(int fd, tuc::Request &request, ucred &credentials, int (&descriptors)[2]) {
    iovec data{&request, sizeof(request)};
    alignas(cmsghdr) char control[CMSG_SPACE(sizeof(ucred)) + CMSG_SPACE(2 * sizeof(int))] = {};
    msghdr message{};
    message.msg_iov = &data;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    ssize_t received;
    do { received = recvmsg(fd, &message, MSG_CMSG_CLOEXEC); } while (received < 0 && errno == EINTR);
    bool authenticated = false;
    int count = 0;
    for (cmsghdr *c = CMSG_FIRSTHDR(&message); received > 0 && c; c = CMSG_NXTHDR(&message, c)) {
        if (c->cmsg_level != SOL_SOCKET) continue;
        if (c->cmsg_type == SCM_CREDENTIALS && c->cmsg_len == CMSG_LEN(sizeof(ucred))) {
            memcpy(&credentials, CMSG_DATA(c), sizeof(credentials));
            authenticated = true;
        } else if (c->cmsg_type == SCM_RIGHTS && c->cmsg_len >= CMSG_LEN(sizeof(int))) {
            size_t number = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            for (size_t i = 0; i < number; ++i) {
                int descriptor;
                memcpy(&descriptor, CMSG_DATA(c) + i * sizeof(int), sizeof(descriptor));
                if (count < 2) descriptors[count] = descriptor;
                else close(descriptor);
                ++count;
            }
        }
    }
    bool ok = received > 0 && authenticated && count == 2 &&
        !(message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) &&
        transfer(fd, reinterpret_cast<char *>(&request) + received, sizeof(request) - received, false);
    if (ok) ok = request.magic == tuc::kMagic && tuc::regular_uid(request.uid) && tuc::package_name(request.package);
    struct stat first{}, second{};
    if (ok) ok = fstat(descriptors[0], &first) == 0 && fstat(descriptors[1], &second) == 0 &&
        S_ISFIFO(first.st_mode) && S_ISREG(second.st_mode) && second.st_size == kAckSize &&
        (first.st_dev != second.st_dev || first.st_ino != second.st_ino) &&
        (fcntl(descriptors[0], F_GETFL) & O_ACCMODE) == O_RDONLY;
    if (ok) {
        int seals = fcntl(descriptors[1], F_GET_SEALS);
        ok = seals >= 0 && (seals & (F_SEAL_SHRINK | F_SEAL_GROW)) == (F_SEAL_SHRINK | F_SEAL_GROW);
    }
    if (!ok) {
        for (int &descriptor : descriptors) { if (descriptor >= 0) close(descriptor); descriptor = -1; }
        if (received == 0) errno = ECONNRESET;
        else if (received > 0) errno = EPROTO;
    }
    return ok;
}

bool read_pipe(int fd, void *data, size_t size) {
    pollfd ready{fd, POLLIN, 0};
    int polled = poll(&ready, 1, 3000);
    if (polled <= 0) { if (polled == 0) errno = ETIMEDOUT; return false; }
    ssize_t received;
    do { received = read(fd, data, size); } while (received < 0 && errno == EINTR);
    if (received == static_cast<ssize_t>(size)) return true;
    if (received >= 0) errno = received == 0 ? EPIPE : EPROTO;
    return false;
}

bool write_pipe(int fd, const void *data, size_t size) {
    pollfd ready{fd, POLLOUT, 0};
    int polled = poll(&ready, 1, 3000);
    if (polled <= 0) { if (polled == 0) errno = ETIMEDOUT; return false; }
    // Ignore only this write's SIGPIPE on this thread; never change the app's signal handlers.
    sigset_t blocked, previous, pending;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGPIPE);
    int mask_error = pthread_sigmask(SIG_BLOCK, &blocked, &previous);
    if (mask_error) { errno = mask_error; return false; }
    sigpending(&pending);
    ssize_t sent;
    do { sent = write(fd, data, size); } while (sent < 0 && errno == EINTR);
    int error = errno;
    if (sent < 0 && error == EPIPE && !sigismember(&pending, SIGPIPE)) {
        timespec zero{};
        (void)sigtimedwait(&blocked, nullptr, &zero);
    }
    (void)pthread_sigmask(SIG_SETMASK, &previous, nullptr);
    errno = error;
    return sent == static_cast<ssize_t>(size);
}

bool identity(pid_t pid, unsigned &uid, pid_t &parent, int process = -1) {
    char path[64], line[256];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    int fd = process >= 0 ? openat(process, "status", O_RDONLY | O_CLOEXEC) : open(path, O_RDONLY | O_CLOEXEC);
    FILE *status = fd < 0 ? nullptr : fdopen(fd, "r");
    if (!status && fd >= 0) close(fd);
    if (!status) return false;
    bool got_uid = false, got_parent = false;
    while (fgets(line, sizeof(line), status)) {
        unsigned real, effective, saved, filesystem;
        if (sscanf(line, "Uid: %u %u %u %u", &real, &effective, &saved, &filesystem) == 4) {
            uid = real;
            got_uid = real == effective && real == saved && real == filesystem;
        }
        if (sscanf(line, "PPid: %d", &parent) == 1) got_parent = true;
    }
    fclose(status);
    return got_uid && got_parent && parent > 1;
}

void heartbeat(pid_t parent) {
    char path[128], contents[64];
    snprintf(path, sizeof(path), "%s/zygisk%zu", kRuntime, sizeof(void *) * 8);
    int n = snprintf(contents, sizeof(contents), "%d\n", parent);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd >= 0) {
        (void)write(fd, contents, n);
        close(fd);
    }
}

[[noreturn]] void worker_exit(int fd, Result result) {
    (void)write(fd, &result, sizeof(result));
    _exit(result.phase == Applied ? 0 : 1);
}

Result mount_snapshot(pid_t pid, pid_t parent, int snapshot, uint32_t uid, int process = -1) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/ns/mnt", pid);
    int ns = process >= 0 ? openat(process, "ns/mnt", O_RDONLY | O_CLOEXEC) : open(path, O_RDONLY | O_CLOEXEC);
    if (ns < 0) return {NamespaceOpen, errno};
    snprintf(path, sizeof(path), "/proc/%d/ns/mnt", parent);
    struct stat app_stat{}, zygote_stat{};
    if (fstat(ns, &app_stat) != 0 || stat(path, &zygote_stat) != 0) {
        int error = errno;
        close(ns);
        return {NamespaceStat, error};
    }
    if (app_stat.st_ino == zygote_stat.st_ino && app_stat.st_dev == zygote_stat.st_dev) {
        close(ns);
        return {NamespaceShared, 0};
    }
    int sources[3] = {-1, -1, -1};
    sources[0] = openat(snapshot, "system", O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (sources[0] < 0) {
        int error = errno;
        close(ns);
        return {SystemSource, error};
    }
    sources[1] = openat(snapshot, "apex", O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (sources[1] < 0 && errno != ENOENT) {
        int error = errno;
        close(sources[0]);
        close(ns);
        return {ApexSource, error};
    }
    sources[2] = tuc::open_user_snapshot(snapshot, uid);
    if (sources[2] < 0 && errno != ENOENT) {
        int error = errno;
        close(ns);
        for (int source : sources) if (source >= 0) close(source);
        return {UserSource, error};
    }
    const Phase source_phases[3] = {SystemSource, ApexSource, UserSource};
    const Phase bind_phases[3] = {SystemBind, ApexBind, UserBind};
    const Phase readonly_phases[3] = {SystemReadonly, ApexReadonly, UserReadonly};
    char source_paths[3][64];
    for (int i = 0; i < 3; ++i) snprintf(source_paths[i], sizeof(source_paths[i]), "/proc/self/fd/%d", sources[i]);
    char resolved[3][PATH_MAX] = {};
    struct stat expected[3]{};
    for (int i = 0; i < 3; ++i) {
        if (sources[i] < 0) continue;
        ssize_t length = readlink(source_paths[i], resolved[i], sizeof(resolved[i]) - 1);
        if (length <= 0 || length >= static_cast<ssize_t>(sizeof(resolved[i]) - 1) || fstat(sources[i], &expected[i]) != 0) {
            int error = length >= static_cast<ssize_t>(sizeof(resolved[i]) - 1) ? ENAMETOOLONG : errno;
            close(ns);
            for (int source : sources) if (source >= 0) close(source);
            return {source_phases[i], error};
        }
    }
    char user_target[80];
#ifdef TUC_DIAGNOSTIC
    snprintf(user_target, sizeof(user_target), "%s", kUser);
#else
    snprintf(user_target, sizeof(user_target), "/data/misc/user/%u/cacerts-added", uid / 100000);
#endif
    const char *targets[3] = {kSystem, kApex, user_target};
    int response[2];
    if (pipe2(response, O_CLOEXEC) != 0) {
        int error = errno;
        close(ns);
        for (int source : sources) if (source >= 0) close(source);
        return {WorkerPipe, error};
    }
    pid_t worker = fork();
    int fork_error = errno;
    if (worker == 0) {
        close(response[0]);
        // The companion handles requests on multiple threads; only syscall wrappers run after fork.
        if (setns(ns, CLONE_NEWNS) != 0) worker_exit(response[1], {NamespaceEnter, errno});
        if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0) worker_exit(response[1], {PropagationPrivate, errno});
        struct stat target{};
        int apex_status = stat(kApex, &target);
        int apex_error = errno;
        bool apex_exists = apex_status == 0 && S_ISDIR(target.st_mode);
        if ((apex_status < 0 && apex_error != ENOENT) || (apex_status == 0 && !apex_exists) ||
            apex_exists != (sources[1] >= 0)) worker_exit(response[1], {ApexTarget, apex_status < 0 ? apex_error : ENOTDIR});
        if (stat(kSystem, &target) != 0) worker_exit(response[1], {SystemTarget, errno});
        if (!S_ISDIR(target.st_mode)) worker_exit(response[1], {SystemTarget, ENOTDIR});
        if (sources[2] >= 0) {
            if (stat(user_target, &target) != 0) worker_exit(response[1], {UserTarget, errno});
            if (!S_ISDIR(target.st_mode)) worker_exit(response[1], {UserTarget, ENOTDIR});
        }
        int applied[3], count = 0;
        for (int i = 0; i < 3; ++i) {
            if (sources[i] < 0) continue;
            // A foreign-namespace O_PATH mount reference cannot be used as a bind source.
            int source_status = stat(resolved[i], &target);
            if (source_status != 0 || target.st_dev != expected[i].st_dev || target.st_ino != expected[i].st_ino) {
                int error = source_status != 0 ? errno : ESTALE;
                while (count > 0) umount2(targets[applied[--count]], MNT_DETACH);
                worker_exit(response[1], {source_phases[i], error});
            }
            const char *source = resolved[i];
            if (mount(source, targets[i], nullptr, MS_BIND, nullptr) != 0) {
                int error = errno;
                while (count > 0) umount2(targets[applied[--count]], MNT_DETACH);
                worker_exit(response[1], {bind_phases[i], error});
            }
            applied[count++] = i;
            if (mount(nullptr, targets[i], nullptr, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) != 0) {
                int error = errno;
                while (count > 0) umount2(targets[applied[--count]], MNT_DETACH);
                worker_exit(response[1], {readonly_phases[i], error});
            }
        }
        worker_exit(response[1], {Applied, 0});
    }
    close(response[1]);
    close(ns);
    for (int source : sources) if (source >= 0) close(source);
    if (worker < 0) {
        close(response[0]);
        return {WorkerFork, fork_error};
    }
    // Read a private result pipe: providers may reap children or ignore SIGCHLD.
    pollfd completed{response[0], POLLIN, 0};
    Result result{WorkerReply, 0};
    int polled = poll(&completed, 1, 2000);
    ssize_t response_size = polled > 0 ? read(response[0], &result, sizeof(result)) : -1;
    bool done = response_size == sizeof(result);
    int response_error = response_size >= 0 ? EPIPE : errno;
    close(response[0]);
    // Never signal a numeric PID: the provider may already have reaped and recycled it.
    int status;
    (void)waitpid(worker, &status, done ? 0 : WNOHANG);
    if (!done) return {polled == 0 ? WorkerTimeout : WorkerReply, polled == 0 ? ETIMEDOUT : response_error};
    return result;
}

void companion(int client) {
    timeout(client);
    int enabled = 1;
    if (setsockopt(client, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)) != 0) return;
    uint8_t hello = 1;
    if (!transfer(client, &hello, 1, true)) return;
    ucred peer{};
    unsigned uid = 0;
    pid_t parent = 0;
    tuc::Request request;
    int channels[2] = {-1, -1};
    // Only the initial Zygote-domain socket message carries credentials and private pipe FDs.
    if (!receive_request(client, request, peer, channels)) {
        log_phase(0, "<handshake>", {PipeDescriptors, errno});
        return;
    }
    char process_path[64];
    snprintf(process_path, sizeof(process_path), "/proc/%d", peer.pid);
    int process = open(process_path, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (peer.uid != 0 || process < 0 || !identity(peer.pid, uid, parent, process) || uid != 0 || !tuc::zygote_process(parent)) {
        log_result(peer.pid, "<handshake>", "rejected sender UID or Zygote parent identity");
        if (process >= 0) close(process);
        close(channels[0]); close(channels[1]);
        return;
    }
    void *memory = mmap(nullptr, kAckSize, PROT_READ | PROT_WRITE, MAP_SHARED, channels[1], 0);
    int map_error = errno;
    close(channels[1]);
    if (memory == MAP_FAILED) {
        log_phase(peer.pid, request.package, {AckMap, map_error});
        close(process); close(channels[0]);
        return;
    }
    auto *acknowledgement = static_cast<uint32_t *>(memory);
    heartbeat(parent);
    int snapshot = open("/dev/trustusercerts/current", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int app_snapshot = snapshot < 0 ? -1 : tuc::open_effective_snapshot(snapshot, request);
    uint8_t selected = app_snapshot >= 0;
    if (!selected && errno != ENOENT) log_phase(peer.pid, request.package, {AppSnapshot, errno});
    uint8_t hook_flags = 0;
    if (selected && !tuc::read_hook_flags(app_snapshot, hook_flags)) {
        log_phase(peer.pid, request.package, {HookPolicy, errno});
        selected = 0;
    }
    if (selected) selected |= hook_flags << 1;
    if (snapshot >= 0) close(snapshot);
    if (!transfer(client, &selected, 1, true) || !selected) {
        if (app_snapshot >= 0) close(app_snapshot);
        close(process); close(channels[0]); munmap(memory, kAckSize);
        return;
    }
    Ready ready{};
    pid_t final_parent = 0;
    Result outcome{Applied, 0};
    char detail[160] = {};
    if (!read_pipe(channels[0], &ready, sizeof(ready))) {
        outcome = {ReadyReceive, errno};
    } else if (ready.phase == ExemptFd || ready.phase == Unshare) {
        outcome = {ready.phase, ready.error};
    } else if (ready.phase != Applied) {
        outcome = {ReadyProtocol, EPROTO};
    } else if (!identity(peer.pid, uid, final_parent, process) || uid != request.uid || parent != final_parent) {
        outcome = {FinalIdentity, errno};
    } else {
        outcome = mount_snapshot(peer.pid, parent, app_snapshot, request.uid, process);
    }
    if (outcome.phase == FinalIdentity) {
        snprintf(detail, sizeof(detail), "expected_uid=%u observed_uid=%u parent=%d expected_parent=%d",
                 request.uid, uid, final_parent, parent);
    }
    close(app_snapshot); close(process);
    log_phase(peer.pid, request.package, outcome, detail);
    __atomic_store_n(acknowledgement, outcome.phase == Applied ? 1u : 2u, __ATOMIC_RELEASE);
    munmap(memory, kAckSize);
    if (hook_flags && outcome.phase == Applied) {
        tuc::HookReport report;
        bool received = read_pipe(channels[0], &report, sizeof(report));
        char message[160];
        if (received && tuc::valid_hook_report(report, hook_flags)) {
            snprintf(message, sizeof(message), "hooks requested=%u active=%u", hook_flags, report.active);
        } else {
            snprintf(message, sizeof(message), "hooks requested=%u result unavailable errno=%d", hook_flags, received ? EPROTO : errno);
        }
        log_result(peer.pid, request.package, message);
    }
    close(channels[0]);
}

class Module : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override { api_ = api; env_ = env; }
    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        struct Unload {
            zygisk::Api *api;
            bool retain = false;
            ~Unload() { if (!retain) api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY); }
        } unload{api_};
        if (!tuc::regular_uid(args->uid) || !args->app_data_dir ||
            (args->is_child_zygote && *args->is_child_zygote)) return;
        tuc::Request request;
        request.uid = args->uid;
        const char *path = env_->GetStringUTFChars(args->app_data_dir, nullptr);
        if (!path) return;
        bool valid = tuc::package_from_path(path, request.uid, request.package);
        env_->ReleaseStringUTFChars(args->app_data_dir, path);
        if (!valid) return;
        int fd = api_->connectCompanion();
        if (fd < 0) return;
        timeout(fd);
        int ready_pipe[2] = {-1, -1};
        uint32_t *acknowledgement = nullptr;
        int ack_fd = create_ack(acknowledgement);
        if (ack_fd < 0 || pipe2(ready_pipe, O_CLOEXEC) != 0) {
            if (ready_pipe[0] >= 0) { close(ready_pipe[0]); close(ready_pipe[1]); }
            if (ack_fd >= 0) close(ack_fd);
            if (acknowledgement) munmap(acknowledgement, kAckSize);
            close(fd);
            return;
        }
        uint8_t selected = 0, hello = 0;
        bool ok = transfer(fd, &hello, 1, false) && hello == 1 &&
                  send_request(fd, request, ready_pipe[0], ack_fd) &&
                  transfer(fd, &selected, 1, false) && tuc::selected_response(selected);
        close(ready_pipe[0]); close(ack_fd); close(fd);
        if (!ok) { close(ready_pipe[1]); munmap(acknowledgement, kAckSize); return; }
        Ready failure{};
        errno = 0;
        if (!api_->exemptFd(ready_pipe[1])) failure = {ExemptFd, errno};
        else if (unshare(CLONE_NEWNS) != 0) failure = {Unshare, errno};
        if (failure.phase != Applied) {
            (void)write_pipe(ready_pipe[1], &failure, sizeof(failure));
            close(ready_pipe[1]); munmap(acknowledgement, kAckSize);
            return;
        }
        ready_ = ready_pipe[1];
        acknowledgement_ = acknowledgement;
        hook_flags_ = selected >> 1;
        if (hook_flags_) {
            uid_ = request.uid;
            memcpy(package_, request.package, sizeof(package_));
            preload_hooks();
            unload.retain = true;
        }
    }
    void postAppSpecialize(const zygisk::AppSpecializeArgs *) override {
        if (ready_ < 0) return;
        Ready ready{Applied, 0};
        uint32_t applied = write_pipe(ready_, &ready, sizeof(ready)) ? wait_ack(acknowledgement_) : 0;
        int error = errno;
        munmap(acknowledgement_, kAckSize);
        acknowledgement_ = nullptr;
        if (hook_flags_) {
            int active = 0;
            if (applied == 1 && getuid() == uid_ && geteuid() == uid_ && install_)
                active = install_(env_, dex_, dex_size_, hook_flags_);
            if (active < 0 || (active & ~hook_flags_)) active = 0;
            char message[160];
            snprintf(message, sizeof(message), "hooks requested=%u active=%d mount_ack=%u errno=%d", hook_flags_, active, applied, applied ? 0 : error);
            __android_log_print(ANDROID_LOG_INFO, "TrustUserCertificates", "package=%s %s", package_, message);
            if (applied == 1) {
                tuc::HookReport report{tuc::kMagic, hook_flags_, static_cast<uint32_t>(active)};
                if (!write_pipe(ready_, &report, sizeof(report)))
                    __android_log_print(ANDROID_LOG_ERROR, "TrustUserCertificates", "package=%s hook report failed errno=%d", package_, errno);
            }
        }
        close(ready_);
        ready_ = -1;
    }
private:
    void preload_hooks() {
#if defined(__aarch64__)
        constexpr char library[] = "arm64-v8a.so";
#elif defined(__arm__)
        constexpr char library[] = "armeabi-v7a.so";
#elif defined(__x86_64__)
        constexpr char library[] = "x86_64.so";
#elif defined(__i386__)
        constexpr char library[] = "x86.so";
#else
#error Unsupported hook architecture
#endif
        int module = api_->getModuleDir();
        int hooks = module < 0 ? -1 : openat(module, "hooks", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        int engine = hooks < 0 ? -1 : openat(hooks, library, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        int dex = module < 0 ? -1 : openat(module, "hooks.dex", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        struct stat engine_stat{}, dex_stat{};
        bool valid = engine >= 0 && dex >= 0 && fstat(engine, &engine_stat) == 0 && S_ISREG(engine_stat.st_mode) &&
            fstat(dex, &dex_stat) == 0 && S_ISREG(dex_stat.st_mode) && dex_stat.st_size > 0 && dex_stat.st_size <= 16 * 1024 * 1024;
        const char *reason = "missing or invalid hook assets";
        if (valid) {
            dex_size_ = static_cast<size_t>(dex_stat.st_size);
            void *mapping = mmap(nullptr, dex_size_, PROT_READ, MAP_PRIVATE, dex, 0);
            if (mapping != MAP_FAILED) {
                android_dlextinfo options{};
                options.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
                options.library_fd = engine;
                void *handle = android_dlopen_ext("libtrustusercerts-hooks.so", RTLD_NOW | RTLD_LOCAL, &options);
                if (handle) {
                    auto install = reinterpret_cast<Install>(dlsym(handle, "tuc_hooks_install"));
                    auto prepare = reinterpret_cast<int (*)(JNIEnv *)>(dlsym(handle, "tuc_hooks_prepare"));
                    if (!install || !prepare) { reason = "hook engine has no prepare/install entry"; dlclose(handle); }
                    // LSPlant needs Zygote's JNI access; app trust sources initialize only after specialization.
                    else if (prepare(env_) == 1) { install_ = install; dex_ = mapping; }
                    else reason = "hook engine prepare failed";
                    // A prepare attempt may leave ART callbacks installed even on failure; retain the engine.
                } else reason = dlerror();
                // A successful engine keeps this mapping for its InMemoryDexClassLoader.
                if (!install_) munmap(mapping, dex_size_);
            } else reason = "hook dex mmap failed";
        }
        if (!install_) __android_log_print(ANDROID_LOG_ERROR, "TrustUserCertificates", "package=%s %s", package_, reason ? reason : "hook engine preload failed");
        if (engine >= 0) close(engine);
        if (dex >= 0) close(dex);
        if (hooks >= 0) close(hooks);
        if (module >= 0) close(module);
    }
    using Install = int (*)(JNIEnv *, const void *, size_t, uint8_t);
    Install install_ = nullptr;
    void *dex_ = nullptr;
    size_t dex_size_ = 0;
    uint8_t hook_flags_ = 0;
    uint32_t uid_ = 0;
    char package_[256] = {};
    zygisk::Api *api_ = nullptr;
    JNIEnv *env_ = nullptr;
    int ready_ = -1;
    uint32_t *acknowledgement_ = nullptr;
};
} // namespace

REGISTER_ZYGISK_MODULE(Module)
REGISTER_ZYGISK_COMPANION(companion)
