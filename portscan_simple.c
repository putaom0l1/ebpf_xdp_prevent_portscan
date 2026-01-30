#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>     // IPPROTO_TCP
#include <linux/tcp.h>

#define XDP_PASS 2
#define XDP_DROP 1

//30 扫描端口 >=24 就阻断+告警 =====
#define WINDOW_NS       (30ULL * 1000000000ULL)
#define PORT_THRESHOLD  24

// per-IP 状态：窗口/计数/阻断
struct scan_record {
    __u64 window_start_ns;   // 当前窗口起点（滑动窗口：从第一次/重置开始算）
    __u32 epoch;             // 窗口代数（窗口重置时 epoch++，用于区分 seen_ports 的旧记录）
    __u32 unique_ports;      // 当前窗口内已出现的不同端口数
    __u16 last_port;         // 新端口
    __u8  blocked;           // 是否drop（1 == drop）
    __u8  _pad;
};


struct port_key {
    __u32 src_ip;            // 网络字节序
    __u32 epoch;             // 对应 scan_record.epoch
    __u16 port;              // 主机字节序端口
    __u16 _pad;
};

// ringbuf 事件：用户态打印
struct alert_event {
    __u32 src_ip;            // 网络字节序
    __u16 port;              // 主机字节序
    __u16 _pad;
    __u32 unique_ports;      // 当前窗口已出现的不同端口数（会 >=24，并继续增长）
    __u64 total_alerts;      // 全局告警次数（每次告警都 +1）
    __u8  blocked;           // 1 表示处于阻断状态（触发阈值后以及之后）
    __u8  reason;            // 0=触发阈值那一次；1=阻断后新增端口
    __u16 _pad2;
};

struct bpf_map_def SEC("maps") scan_tracker = {
    .type        = BPF_MAP_TYPE_LRU_HASH,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(struct scan_record),
    .max_entries = 4096,
};

// 记录“这个窗口里这个端口是否出现过”
struct bpf_map_def SEC("maps") seen_ports = {
    .type        = BPF_MAP_TYPE_LRU_HASH,
    .key_size    = sizeof(struct port_key),
    .value_size  = sizeof(__u8),
    // 65535 * 3 == 196,605，我就kali和主机两个模拟攻击机，足够了
    .max_entries = 196605,
};

struct bpf_map_def SEC("maps") alert_counter = {
    .type        = BPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u64),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") events = {
    .type        = BPF_MAP_TYPE_RINGBUF,
    .key_size    = 0,
    .value_size  = 0,
    .max_entries = 1 << 24,  // 16MB：足够容纳大量告警事件
};

static __always_inline int emit_alert(__u32 src_ip, __u16 port, __u32 unique_ports, __u8 blocked, __u8 reason) {
    __u32 k = 0;
    __u64 total = 0;
    __u64 *cnt = bpf_map_lookup_elem(&alert_counter, &k);
    if (cnt) {
        total = __sync_fetch_and_add(cnt, 1) + 1;
    }

    struct alert_event ev = {};
    ev.src_ip = src_ip;
    ev.port = port;
    ev.unique_ports = unique_ports;
    ev.total_alerts = total;
    ev.blocked = blocked;
    ev.reason = reason;

    // ringbuf 写失败时直接忽略（可能是 ringbuf 满了）
    bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
    return 0;
}

SEC("xdp")
int detect_portscan(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(*ip))
        return XDP_PASS;
    if ((void *)ip + ip_hdr_len + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (struct tcphdr *)((void *)ip + ip_hdr_len);
    if (!(tcp->syn == 1 && tcp->ack == 0))
        return XDP_PASS;

    __u32 src_ip = ip->saddr;             
    __u16 dst_port = bpf_ntohs(tcp->dest);
    __u64 now = bpf_ktime_get_ns();

    struct scan_record *rec = bpf_map_lookup_elem(&scan_tracker, &src_ip);
    if (!rec) {
        struct scan_record new_rec = {};
        new_rec.window_start_ns = now;
        new_rec.epoch = 0;
        new_rec.unique_ports = 0;
        new_rec.last_port = 0;
        new_rec.blocked = 0;
        bpf_map_update_elem(&scan_tracker, &src_ip, &new_rec, BPF_ANY);
        rec = bpf_map_lookup_elem(&scan_tracker, &src_ip);
        if (!rec)
            return XDP_PASS;
    }

    // 窗口过期：重置窗口
    if (now - rec->window_start_ns > WINDOW_NS) {
        rec->window_start_ns = now;
        rec->epoch += 1;
        rec->unique_ports = 0;
        rec->last_port = 0;
        rec->blocked = 0;
    }

    // 判断是否新端口
    // 去重用的是seen_ports（src_ip + epoch + port）
    struct port_key pk = {};
    pk.src_ip = src_ip;
    pk.epoch = rec->epoch;
    pk.port = dst_port;

    __u8 *seen = bpf_map_lookup_elem(&seen_ports, &pk);
    if (seen) {
        // 判断是否为重复端口，是不是都drop
        return XDP_DROP;
    }

    // 新端口：写入 seen_ports
    __u8 one = 1;
    bpf_map_update_elem(&seen_ports, &pk, &one, BPF_ANY);

    // 更新计数与最近端口
    rec->unique_ports += 1;
    rec->last_port = dst_port;

    // 1) 未阻断且达到阈值：告警+drop
    if (!rec->blocked && rec->unique_ports >= PORT_THRESHOLD) {
        rec->blocked = 1;
        emit_alert(src_ip, dst_port, rec->unique_ports, 1 /*blocked*/, 0 /*threshold*/);
        return XDP_DROP; // 刚好达到阈值这一包也drop
    }

    // 2) 每出现一个新端口，告警
    if (rec->blocked) {
        emit_alert(src_ip, dst_port, rec->unique_ports, 1 /*blocked*/, 1 /*post-block new port*/);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";