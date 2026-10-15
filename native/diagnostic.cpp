// Exercises the production IPC and mount helpers in a disposable process namespace.
#define TUC_DIAGNOSTIC
#include "module.cpp"
#include <stdlib.h>

struct ObservedStore { uint64_t device; uint64_t inode; int32_t error; };
struct AppReport { ObservedStore stores[3]; int32_t socket_result; int32_t socket_error; uint32_t ack; };

static ObservedStore observe_store(const char *path) {
    struct stat value{};
    if (stat(path, &value) != 0) return {0, 0, errno};
    return {static_cast<uint64_t>(value.st_dev), static_cast<uint64_t>(value.st_ino), 0};
}

int main(int argc, char **argv) {
    if (getuid() != 0 || (argc != 4 && argc != 5) || !tuc::package_name(argv[1])) {
        fprintf(stderr, "Usage (root): trustusercerts-diagnostic PACKAGE UID FIXTURE_SNAPSHOT [APP_SELINUX_CONTEXT]\nUses /dev/trustusercerts-check/{system,apex,user}, never real trust stores.\n");
        return 2;
    }
    char *end = nullptr;
    unsigned long number = strtoul(argv[2], &end, 10);
    if (!end || *end || number > UINT32_MAX || !tuc::regular_uid(number)) return 2;
    tuc::Request request;
    request.uid = number;
    memcpy(request.package, argv[1], strlen(argv[1]) + 1);
    int snapshot = open(argv[3], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int app_snapshot = snapshot < 0 ? -1 : tuc::open_effective_snapshot(snapshot, request);
    if (snapshot >= 0) close(snapshot);
    if (app_snapshot < 0) {
        fprintf(stderr, "No selected package or enabled global snapshot (errno=%d).\n", errno);
        return 1;
    }
    int sources[3] = {
        openat(app_snapshot, "system", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW),
        openat(app_snapshot, "apex", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW),
        tuc::open_user_snapshot(app_snapshot, request.uid),
    };
    if (sources[0] < 0) { perror("system source"); return 1; }
    bool has_source[3] = {true, sources[1] >= 0, sources[2] >= 0};
    ObservedStore expected[3]{};
    for (int i = 0; i < 3; ++i) {
        if (sources[i] < 0) continue;
        struct stat source{};
        if (fstat(sources[i], &source) != 0) return 1;
        expected[i] = {static_cast<uint64_t>(source.st_dev), static_cast<uint64_t>(source.st_ino), 0};
        close(sources[i]);
    }
    ObservedStore original[4] = {observe_store(kSystem), observe_store(kApex), observe_store(kUser), observe_store("/proc/self/ns/mnt")};
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0) { perror("socketpair"); return 1; }
    int enabled = 1;
    if (setsockopt(sockets[0], SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)) != 0) return 1;
    timeout(sockets[0]);
    timeout(sockets[1]);
    pid_t parent = getpid();
    pid_t child = fork();
    if (child < 0) { perror("fork"); return 1; }
    if (child == 0) {
        close(sockets[0]);
        close(app_snapshot);
        if (argc == 5) {
            int context = open("/proc/self/attr/current", O_WRONLY | O_CLOEXEC);
            const char zygote[] = "u:r:zygote:s0";
            if (context < 0 || write(context, zygote, sizeof(zygote)) != sizeof(zygote)) _exit(10);
            close(context);
        }
        int ready_pipe[2];
        uint32_t *acknowledgement = nullptr;
        int ack_fd = create_ack(acknowledgement);
        if (ack_fd < 0 || pipe2(ready_pipe, O_CLOEXEC) != 0) _exit(11);
        uint8_t hello = 0, selected_ack = 0;
        if (!transfer(sockets[1], &hello, 1, false) || hello != 1 ||
            !send_request(sockets[1], request, ready_pipe[0], ack_fd) ||
            !transfer(sockets[1], &selected_ack, 1, false) || selected_ack != 1) _exit(3);
        close(ready_pipe[0]); close(ack_fd);
        Ready ready{Applied, 0};
        if (unshare(CLONE_NEWNS) != 0) ready = {Unshare, errno};
        if (ready.phase == Applied && (setresgid(request.uid, request.uid, request.uid) != 0 ||
            setresuid(request.uid, request.uid, request.uid) != 0)) ready = {FinalIdentity, errno};
        if (ready.phase == Applied && argc == 5) {
            int context = open("/proc/self/attr/current", O_WRONLY | O_CLOEXEC);
            if (context < 0 || write(context, argv[4], strlen(argv[4]) + 1) != static_cast<ssize_t>(strlen(argv[4]) + 1))
                ready = {FinalIdentity, errno};
            if (context >= 0) close(context);
        }
        AppReport report{};
        errno = 0;
        report.socket_result = send(sockets[1], &hello, 1, MSG_NOSIGNAL);
        report.socket_error = errno;
        close(sockets[1]);
        if (!write_pipe(ready_pipe[1], &ready, sizeof(ready))) _exit(4);
        report.ack = wait_ack(acknowledgement);
        if (!report.ack) {
            report.stores[0].error = errno;
            (void)write_pipe(ready_pipe[1], &report, sizeof(report));
            _exit(5);
        }
        report.stores[0] = observe_store(kSystem);
        report.stores[1] = observe_store(kApex);
        report.stores[2] = observe_store(kUser);
        if (!write_pipe(ready_pipe[1], &report, sizeof(report))) _exit(6);
        munmap(acknowledgement, kAckSize);
        _exit(report.ack == 1 ? 0 : 7);
    }
    close(sockets[1]);
    char process_path[64];
    snprintf(process_path, sizeof(process_path), "/proc/%d", child);
    int process = open(process_path, O_PATH | O_DIRECTORY | O_CLOEXEC);
    uint8_t hello = 1;
    ucred peer{};
    tuc::Request received;
    int channels[2] = {-1, -1};
    bool authenticated = transfer(sockets[0], &hello, 1, true) &&
        receive_request(sockets[0], received, peer, channels) &&
        peer.pid == child && peer.uid == 0 && !memcmp(&received, &request, sizeof(request));
    void *memory = authenticated ? mmap(nullptr, kAckSize, PROT_READ | PROT_WRITE, MAP_SHARED, channels[1], 0) : MAP_FAILED;
    if (channels[1] >= 0) close(channels[1]);
    authenticated = authenticated && memory != MAP_FAILED;
    uint8_t selected_ack = authenticated;
    (void)transfer(sockets[0], &selected_ack, 1, true);
    Ready ready{};
    Result result{ReadyReceive, 0};
    bool post = authenticated && read_pipe(channels[0], &ready, sizeof(ready));
    close(sockets[0]);
    unsigned observed_uid = 0;
    pid_t observed_parent = 0;
    if (!post) result.error = errno;
    else if (ready.phase != Applied) result = {ready.phase, ready.error};
    else if (!identity(child, observed_uid, observed_parent, process) || observed_uid != request.uid || observed_parent != parent)
        result = {FinalIdentity, errno};
    else {
        char context[256] = {};
        int context_fd = openat(process, "attr/current", O_RDONLY | O_CLOEXEC);
        ssize_t size = context_fd < 0 ? -1 : read(context_fd, context, sizeof(context) - 1);
        int context_error = errno;
        if (context_fd >= 0) close(context_fd);
        if (size > 0 && context[size - 1] == '\n') context[size - 1] = 0;
        fprintf(stdout, "observed_app_context=%s\n", size > 0 ? context : "<unavailable>");
        if (argc == 5 && (size <= 0 || strcmp(context, argv[4]))) result = {FinalIdentity, size <= 0 ? context_error : EPERM};
        else result = mount_snapshot(child, parent, app_snapshot, request.uid, process);
    }
    fprintf(stdout, "phase=%s errno=%d (%s) sender_pid=%d sender_uid=%u\n", phase_name(result.phase),
            result.error, result.error ? strerror(result.error) : "none", peer.pid, observed_uid);
    uint8_t applied = result.phase == Applied;
    if (memory != MAP_FAILED) __atomic_store_n(static_cast<uint32_t *>(memory), applied ? 1u : 2u, __ATOMIC_RELEASE);
    AppReport report{};
    bool observed = channels[0] >= 0 && read_pipe(channels[0], &report, sizeof(report));
    const ObservedStore *actual = report.stores;
    if (observed) fprintf(stdout, "post_socket_result=%d errno=%d ready_pipe_write=yes shared_ack=%u\n", report.socket_result, report.socket_error, report.ack);
    if (observed && actual[0].error) fprintf(stdout, "app_observation_or_ack_errno=%d (%s)\n", actual[0].error, strerror(actual[0].error));
    if (channels[0] >= 0) close(channels[0]);
    if (memory != MAP_FAILED) munmap(memory, kAckSize);
    close(process);
    close(app_snapshot);
    int child_status;
    (void)waitpid(child, &child_status, 0);
    if (WIFEXITED(child_status)) fprintf(stdout, "child_exit=%d\n", WEXITSTATUS(child_status));
    ObservedStore after[4] = {observe_store(kSystem), observe_store(kApex), observe_store(kUser), observe_store("/proc/self/ns/mnt")};
    bool unchanged = true;
    for (int i = 0; i < 4; ++i) {
        if (original[i].device != after[i].device || original[i].inode != after[i].inode || original[i].error != after[i].error) unchanged = false;
    }
    bool visible = observed;
    bool restored = observed;
    for (int i = 0; i < 3; ++i) {
        if (has_source[i] && (actual[i].error != 0 || actual[i].device != expected[i].device || actual[i].inode != expected[i].inode)) visible = false;
        if (actual[i].error != original[i].error || actual[i].device != original[i].device || actual[i].inode != original[i].inode) restored = false;
    }
    fprintf(stdout, "user_store_selected=%s\n", has_source[2] ? "yes" : "no");
    if (!applied) fprintf(stdout, "app_original_stores_restored=%s\n", restored ? "yes" : "no");
    fprintf(stdout, "app_store_matches_snapshot=%s parent_namespace_unchanged=%s\n", visible ? "yes" : "no", unchanged ? "yes" : "no");
    return applied && visible && unchanged ? 0 : 1;
}
