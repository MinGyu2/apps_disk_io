#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

enum io_operation {
    OP_READ = 0,
    OP_WRITE = 1,
};

struct pending_io {
    __s32 fd;
    __u8 op;
};

struct file_io_event {
    __u32 pid;
    __u32 tid;
    __s32 fd;
    __u8 op;
    __u8 padding[3];
    __u64 bytes;
};

/* syscall tracepoint arguments start at offset 16. */
struct sys_enter_fd_ctx {
    __u64 common_and_syscall_id[2];
    __u64 fd;
};

struct sys_exit_ctx {
    __u64 common_and_syscall_id[2];
    __s64 ret;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct pending_io);
} PENDING_IO SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} EVENTS SEC(".maps");

static __always_inline int track_enter(struct sys_enter_fd_ctx *ctx, __u8 op)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct pending_io pending = {
        .fd = (__s32)ctx->fd,
        .op = op,
    };

    if (pending.fd < 0)
        return 0;

    bpf_map_update_elem(&PENDING_IO, &pid_tgid, &pending, BPF_ANY);
    return 0;
}

static __always_inline int track_exit(struct sys_exit_ctx *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct pending_io *pending = bpf_map_lookup_elem(&PENDING_IO, &pid_tgid);

    if (!pending)
        return 0;

    if (ctx->ret > 0) {
        struct file_io_event *event =
            bpf_ringbuf_reserve(&EVENTS, sizeof(*event), 0);

        if (event) {
            event->pid = pid_tgid >> 32;
            event->tid = (__u32)pid_tgid;
            event->fd = pending->fd;
            event->op = pending->op;
            event->padding[0] = 0;
            event->padding[1] = 0;
            event->padding[2] = 0;
            event->bytes = (__u64)ctx->ret;
            bpf_ringbuf_submit(event, 0);
        }
    }

    bpf_map_delete_elem(&PENDING_IO, &pid_tgid);
    return 0;
}

#define ENTER_PROGRAM(syscall_name, operation)                              \
    SEC("tracepoint/syscalls/sys_enter_" #syscall_name)                    \
    int enter_##syscall_name(struct sys_enter_fd_ctx *ctx)                 \
    {                                                                       \
        return track_enter(ctx, operation);                                 \
    }

#define EXIT_PROGRAM(syscall_name)                                         \
    SEC("tracepoint/syscalls/sys_exit_" #syscall_name)                     \
    int exit_##syscall_name(struct sys_exit_ctx *ctx)                      \
    {                                                                       \
        return track_exit(ctx);                                             \
    }

ENTER_PROGRAM(read, OP_READ)
EXIT_PROGRAM(read)
ENTER_PROGRAM(write, OP_WRITE)
EXIT_PROGRAM(write)
ENTER_PROGRAM(pread64, OP_READ)
EXIT_PROGRAM(pread64)
ENTER_PROGRAM(pwrite64, OP_WRITE)
EXIT_PROGRAM(pwrite64)
ENTER_PROGRAM(readv, OP_READ)
EXIT_PROGRAM(readv)
ENTER_PROGRAM(writev, OP_WRITE)
EXIT_PROGRAM(writev)

char LICENSE[] SEC("license") = "GPL";
