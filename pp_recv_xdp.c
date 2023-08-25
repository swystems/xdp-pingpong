// #include <asm/msr.h>
#include <linux/bpf.h>
#include <linux/time.h>
#include <linux/in.h>
#include <linux/ptrace.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/ethtool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add(ptr, val))
#endif

#ifndef lock_fetch
#define lock_fetch(ptr) ((void)__sync_fetch_and_add(ptr, 0))
#endif

static const char NODE01_IPADDR[] = {192, 168, 56, 101};
static const char NODE02_IPADDR[] = {192, 168, 56, 102};
static const int PACKET_PORT = 1234;

static const int MAX_TIMESTAMPS = 1 << 20;

/**
 * Packet structure:
 * ,--------------------------------------------------------,
 * | ethhdr | iphdr | udphdr | round | id | ts1 | ts2 | ts3 |
 * '--------------------------------------------------------'
 * id = 0 -> PING
 * id = 1 -> PONG
 */
struct pp_payload
{
    __u64 round;
    __u8 id;
    __u64 ts1;
    __u64 ts2;
    __u64 ts3;
};

// MAPS
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64[5]);
    __uint(max_entries, MAX_TIMESTAMPS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pp_timestamps
    SEC(".maps");

// static inline __u64 rdtsc(void)
// {
// 	__u64 var;
// 	__u32 hi, lo;

// 	asm volatile
// 	    ("rdtsc" : "=a" (lo), "=d" (hi));

// 	var = ((__u64)hi << 32) | lo;
// 	return (var);
// }

static inline int swap(void *a, void *b, const int size, const void *packet_end)
{
    const void *end = b + size;
    if (end > packet_end)
        return -1;

    __u8 tmp;
    while (b < end)
    {
        tmp = *(__u8 *)a;
        *(__u8 *)a = *(__u8 *)b;
        *(__u8 *)b = tmp;
        ++a;
        ++b;
    }
    return 0;
}

static inline __u64
get_timestamp()
{
    return bpf_ktime_get_ns();
    // return rdtsc();
}

/**
 * Save timestamps in the corresponding map
 *
 * @param payload pointer to the current packet payload
 * @param ts4 last received timestamp
 */
static __u32 save_timestamps(struct pp_payload *payload, __u64 ts4)
{

    __u64 timestamps[5];
    timestamps[0] = payload->round;
    timestamps[1] = payload->ts1;
    timestamps[2] = payload->ts2;
    timestamps[3] = payload->ts3;
    timestamps[4] = ts4;

    if (payload->round >= MAX_TIMESTAMPS)
        return -1;

    bpf_map_update_elem(&pp_timestamps, &payload->round, &timestamps, BPF_ANY);
    return 0;
}

static inline struct ethhdr *parse_ethhdr(void *data, void *data_end)
{
    if (data + sizeof(struct ethhdr) > data_end)
        return NULL;
    return (struct ethhdr *)data;
}

static inline struct iphdr *parse_iphdr(void *data, void *data_end)
{
    void *ip_start = data + sizeof(struct ethhdr);
    if (ip_start + sizeof(struct iphdr) > data_end)
        return NULL;
    return (struct iphdr *)ip_start;
}

static inline struct udphdr *parse_udphdr(void *data, void *data_end)
{
    void *udp_start = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (udp_start + sizeof(struct udphdr) > data_end)
        return NULL;
    return (struct udphdr *)udp_start;
}

static inline __u8
is_valid_ip_packet(struct iphdr *ip)
{
    return (ip->saddr == *((__be32 *)NODE01_IPADDR) && ip->daddr == *((__be32 *)NODE02_IPADDR)) || (ip->saddr == *((__be32 *)NODE02_IPADDR) && ip->daddr == *((__be32 *)NODE01_IPADDR));
}

static inline struct pp_payload *get_payload(void *data, void *data_end)
{

    void *payload_ptr = data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
                        sizeof(struct udphdr);

    if (payload_ptr + sizeof(struct pp_payload) > data_end)
        return NULL;

    return (struct pp_payload *)payload_ptr;
}

SEC(
    "xdp_pp")
int xdp_prog(struct xdp_md *ctx)
{
    __u64 arrival_timestamp = get_timestamp();

    bpf_printk("recvd packet");

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // check headers integrity
    struct ethhdr *eth = parse_ethhdr(data, data_end);
    if (!eth)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = parse_iphdr(data, data_end);
    if (!ip)
        return XDP_PASS;

    if (is_valid_ip_packet(ip) == 0)
        return XDP_PASS;

    struct udphdr *udp = parse_udphdr(data, data_end);
    if (!udp)
        return XDP_PASS;

    if (udp->dest != bpf_htons(PACKET_PORT))
    {
        return XDP_PASS;
    }

    bpf_printk("correct port, processing payload");

    struct pp_payload *payload = get_payload(data, data_end);
    if (!payload)
    {
        return XDP_PASS;
    }

    if (payload->id == 0)
    {
        // PING
        payload->ts2 = arrival_timestamp;

        swap(&eth->h_source, &eth->h_dest, sizeof(eth->h_source), data_end);
        swap(&ip->saddr, &ip->daddr, sizeof(ip->saddr), data_end);
        ip->check = 0;

        bpf_printk("Sending packet back");

        payload->ts3 = get_timestamp();
        payload->id = 1;
        return XDP_TX;
    }
    else if (payload->id == 1)
    {
        // PONG
        save_timestamps(payload, arrival_timestamp);

        return XDP_DROP;
    }

    bpf_printk("unrecognised packet/packet ID");
    // print_hex_dump?

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
