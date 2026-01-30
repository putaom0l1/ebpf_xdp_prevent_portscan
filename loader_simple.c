#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/resource.h>

#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static volatile sig_atomic_t running = 1;

static void on_sig(int sig) {
    (void)sig;
    running = 0;
}

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args) {
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

static void bump_memlock(void) {
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r) != 0) {
        fprintf(stderr, "警告: setrlimit(RLIMIT_MEMLOCK) 失败: %s\n", strerror(errno));
    }
}

struct alert_event {
    __u32 src_ip;
    __u16 port;
    __u16 _pad;
    __u32 unique_ports;
    __u64 total_alerts;
    __u8  blocked;
    __u8  reason;   // 0=阈值触发；1=阻断后新增端口
    __u16 _pad2;
};

static int handle_event(void *ctx, void *data, size_t len) {
    (void)ctx;
    if (len < sizeof(struct alert_event))
        return 0;

    const struct alert_event *e = (const struct alert_event *)data;

    char ipbuf[INET_ADDRSTRLEN] = {0};
    struct in_addr a;
    a.s_addr = e->src_ip;
    inet_ntop(AF_INET, &a, ipbuf, sizeof(ipbuf));

    printf("Big 胆！！！收到ip：%s对我端口%u的扫描，攻击次数为：%u ，已成功阻断%llu次攻击！！！\n",
           ipbuf,
           (unsigned)e->port,
           (unsigned)e->unique_ports,
           (unsigned long long)e->total_alerts);
    return 0;
}

int main(int argc, char **argv) {
    const char *ifname = NULL;
    int ifindex = 0;

    const char *obj_path  = "portscan_simple.o";
    const char *prog_name = "detect_portscan";

    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    int prog_fd = -1;

    int events_fd = -1;
    int counter_fd = -1;

    struct ring_buffer *rb = NULL;
    __u32 xdp_flags = XDP_FLAGS_DRV_MODE;

    if (argc != 2) {
        fprintf(stderr, "用法: %s <接口名>\n示例: sudo %s ens33\n", argv[0], argv[0]);
        return 1;
    }
    ifname = argv[1];

    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    libbpf_set_print(libbpf_print_fn);
    bump_memlock();

    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "错误: 找不到接口 %s\n", ifname);
        return 1;
    }

    printf("基于XDP/eBPF实现的简易端口扫描检测器\n");
    printf("接口: %s (索引: %d)\n", ifname, ifindex);
    printf("同一个ip在30秒内扫描24+端口就丢弃后续数据包\n");
    printf("按 Ctrl+C 退出\n\n");

    obj = bpf_object__open_file(obj_path, NULL);
    if (!obj) {
        fprintf(stderr, "错误: 打开 %s 失败\n", obj_path);
        return 1;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "错误: 加载 BPF 对象失败: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }
    printf("✓ BPF 对象加载成功: %s\n", obj_path);

    prog = bpf_object__find_program_by_name(obj, prog_name);
    if (!prog) {
        fprintf(stderr, "错误: 找不到程序 %s\n", prog_name);
        bpf_object__close(obj);
        return 1;
    }
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "错误: 获取 prog_fd 失败\n");
        bpf_object__close(obj);
        return 1;
    }

    if (bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_DRV_MODE) == 0) {
        xdp_flags = XDP_FLAGS_DRV_MODE;
        printf("XDP 程序已附加到接口 \n");
    } else {
        if (bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_SKB_MODE) == 0) {
            xdp_flags = XDP_FLAGS_SKB_MODE;
            printf("XDP 程序已附加到接口 \n");
        } else {
            fprintf(stderr, "错误: 附加 XDP 失败: %s\n", strerror(errno));
            bpf_object__close(obj);
            return 1;
        }
    }

    events_fd  = bpf_object__find_map_fd_by_name(obj, "events");
    counter_fd = bpf_object__find_map_fd_by_name(obj, "alert_counter");
    if (events_fd < 0 || counter_fd < 0) {
        fprintf(stderr, "错误: 找不到 events 或 alert_counter map\n");
        bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
        bpf_object__close(obj);
        return 1;
    }

    __u32 key = 0;
    __u64 init = 0;
    if (bpf_map_lookup_elem(counter_fd, &key, &init) == 0) {
        printf("[初始化] 当前告警计数 = %llu\n\n", (unsigned long long)init);
    }

    rb = ring_buffer__new(events_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "错误: ring_buffer__new 失败: %s\n", strerror(errno));
        bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
        bpf_object__close(obj);
        return 1;
    }

    while (running) {
        int err = ring_buffer__poll(rb, 1);
        if (err < 0 && errno != EINTR) {
            fprintf(stderr, "警告: ring_buffer__poll 错误: %d (%s)\n", err, strerror(errno));
            break;
        }
    }

    printf("\n收到退出信号，开始卸载...\n");
    ring_buffer__free(rb);
    bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
    bpf_object__close(obj);
    printf("✓ 已卸载 XDP\n");
    return 0;
}
