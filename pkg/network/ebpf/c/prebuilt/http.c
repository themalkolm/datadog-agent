#include "tracer.h"
#include "bpf_helpers.h"
#include "syscalls.h"
#include "ip.h"
#include "ipv6.h"
#include "http.h"
#include "sock.h"

// TODO: Replace those by injected constants based on system configuration
// once we have port range detection merged into the codebase.
#define EPHEMERAL_RANGE_BEG 32768
#define EPHEMERAL_RANGE_END 60999
#define HTTPS_PORT 443

static __always_inline int is_ephemeral_port(u16 port) {
    return port >= EPHEMERAL_RANGE_BEG && port <= EPHEMERAL_RANGE_END;
}

static __always_inline void read_skb_data(struct __sk_buff* skb, u32 offset, char *buffer) {
    if (skb->len - offset < HTTP_BUFFER_SIZE) {
        return;
    }

#pragma unroll
    for (int i = 0; i < HTTP_BUFFER_SIZE; i++) {
        buffer[i] = load_byte(skb, offset + i);
    }
}

SEC("socket/http_filter")
int socket__http_filter(struct __sk_buff* skb) {
    skb_info_t skb_info;

    if (!read_conn_tuple_skb(skb, &skb_info)) {
        return 0;
    }

    // don't bother to inspect packet contents when there is no chance we're dealing with plain HTTP
    if (!(skb_info.tup.metadata&CONN_TYPE_TCP) || skb_info.tup.sport == HTTPS_PORT || skb_info.tup.dport == HTTPS_PORT) {
        return 0;
    }

    // src_port represents the source port number *before* normalization
    // for more context please refer to http-types.h comment on `owned_by_src_port` field
    u16 src_port = skb_info.tup.sport;

    // we normalize the tuple to always be (client, server),
    // so if sport is not in ephemeral port range we flip it
    if (!is_ephemeral_port(skb_info.tup.sport)) {
        flip_tuple(&skb_info.tup);
    }

    char buffer[HTTP_BUFFER_SIZE];
    __builtin_memset(buffer, 0, sizeof(buffer));
    read_skb_data(skb, skb_info.data_off, buffer);
    http_process(buffer, &skb_info, src_port);
    return 0;
}

// This kprobe is used to send batch completion notification to userspace
// because perf events can't be sent from socket filter programs
SEC("kretprobe/tcp_sendmsg")
int kretprobe__tcp_sendmsg(struct pt_regs* ctx) {
    http_notify_batch(ctx);
    return 0;
}

SEC("kprobe/sockfd_lookup_light")
int kprobe__sockfd_lookup_light(struct pt_regs* ctx) {
    int sockfd = (int)PT_REGS_PARM1(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&sockfd_by_pid_tgid, &pid_tgid, &sockfd, BPF_ANY);
    return 0;
}

// this kretprobe is essentially creating an index of (PID, socketfd) to a conn_tuple_t object
SEC("kretprobe/sockfd_lookup_light")
int kretprobe__sockfd_lookup_light(struct pt_regs* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    int *sockfd = bpf_map_lookup_elem(&sockfd_by_pid_tgid, &pid_tgid);
    if (sockfd == NULL) {
        return 0;
    }

    struct socket *socket = (struct socket*)PT_REGS_RC(ctx);
    struct sock *skp;
    bpf_probe_read(&skp, sizeof(skp), &socket->sk);

    conn_tuple_t t = {};
    if (!read_conn_tuple(&t, skp, pid_tgid, CONN_TYPE_TCP)) {
        return 0;
    }

    if (!is_ephemeral_port(t.sport)) {
        flip_tuple(&t);
    }

    u32 pid = pid_tgid & 0xFFFFFFFF;
    bpf_map_delete_elem(&sockfd_by_pid_tgid, &pid_tgid);

    u64 key = ((u64)pid << 32)|(*sockfd);
    bpf_map_update_elem(&tup_by_pid_sockfd, &key, &t, BPF_ANY);
    return 0;
}

// this uprobe is essentially creating an index mapping a SSL context to a conn_tuple_t
SEC("uprobe/SSL_set_fd")
int uprobe__SSL_set_fd(struct pt_regs* ctx) {
    void *ssl_ctx = (void *)PT_REGS_PARM1(ctx);
    int sockfd = (int)PT_REGS_PARM2(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid & 0xFFFFFFFF;
    u64 key = ((u64)pid << 32)|sockfd;
    conn_tuple_t *t = bpf_map_lookup_elem(&tup_by_pid_sockfd, &key);
    if (t == NULL)  {
        return 0;
    }

    // bring map value to eBPF stack so we can write to the other map
    conn_tuple_t t_copy;
    __builtin_memcpy(&t_copy, t, sizeof(conn_tuple_t));
    bpf_map_update_elem(&tup_by_ssl_ctx, &ssl_ctx, &t_copy, BPF_ANY);
    return 0;
}

SEC("uprobe/SSL_read")
int uprobe__SSL_read(struct pt_regs* ctx) {
    ssl_read_args_t args = {0};
    args.ctx = (void *)PT_REGS_PARM1(ctx);
    args.buf = (void *)PT_REGS_PARM2(ctx);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&ssl_read_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int uretprobe__SSL_read(struct pt_regs* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    ssl_read_args_t *args = bpf_map_lookup_elem(&ssl_read_args, &pid_tgid);
    if (args == NULL) {
        return 0;
    }

    conn_tuple_t * t = bpf_map_lookup_elem(&tup_by_ssl_ctx, &args->ctx);
    if (t == NULL) {
        return 0;
    }

    u32 len = (u32)PT_REGS_RC(ctx);
    char buffer[HTTP_BUFFER_SIZE];
    __builtin_memset(buffer, 0, sizeof(buffer));
    if (len >= HTTP_BUFFER_SIZE) {
        bpf_probe_read(buffer, sizeof(buffer), args->buf);
    }

    skb_info_t skb_info = {0};
    __builtin_memcpy(&skb_info.tup, t, sizeof(conn_tuple_t));
    http_process(buffer, &skb_info, skb_info.tup.sport);
    return 0;
}

SEC("uprobe/SSL_write")
int uprobe__SSL_write(struct pt_regs* ctx) {
    void *ssl_ctx = (void *)PT_REGS_PARM1(ctx);
    conn_tuple_t * t = bpf_map_lookup_elem(&tup_by_ssl_ctx, &ssl_ctx);
    if (t == NULL) {
        return 0;
    }

    void *ssl_buffer = (void *)PT_REGS_PARM2(ctx);
    size_t len = (size_t)PT_REGS_PARM3(ctx);
    char buffer[HTTP_BUFFER_SIZE];
    __builtin_memset(buffer, 0, sizeof(buffer));
    if (len >= HTTP_BUFFER_SIZE) {
        bpf_probe_read(buffer, sizeof(buffer), ssl_buffer);
    }

    skb_info_t skb_info = {0};
    __builtin_memcpy(&skb_info.tup, t, sizeof(conn_tuple_t));
    http_process(buffer, &skb_info, skb_info.tup.sport);
    return 0;
}

SEC("uprobe/SSL_shutdown")
int uprobe__SSL_shutdown(struct pt_regs* ctx) {
void *ssl_ctx = (void *)PT_REGS_PARM1(ctx);
    conn_tuple_t * t = bpf_map_lookup_elem(&tup_by_ssl_ctx, &ssl_ctx);
    if (t == NULL) {
        return 0;
    }

    char buffer[HTTP_BUFFER_SIZE];
    __builtin_memset(buffer, 0, sizeof(buffer));

    skb_info_t skb_info = {0};
    __builtin_memcpy(&skb_info.tup, t, sizeof(conn_tuple_t));

    // TODO: this is just a hack. Let's get rid of this skb_info argument altogether
    skb_info.tcp_flags |= TCPHDR_FIN;
    http_process(buffer, &skb_info, skb_info.tup.sport);
    return 0;
}

// This number will be interpreted by elf-loader to set the current running kernel version
__u32 _version SEC("version") = 0xFFFFFFFE; // NOLINT(bugprone-reserved-identifier)

char _license[] SEC("license") = "GPL"; // NOLINT(bugprone-reserved-identifier)
