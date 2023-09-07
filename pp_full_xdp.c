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
#define lock_xadd(ptr, val)    ((void) __sync_fetch_and_add(ptr, val))
#endif

#ifndef lock_fetch
#define lock_fetch(ptr)        ((void) __sync_fetch_and_add(ptr, 0))
#endif

static const char NODE01_IPADDR[] = {192, 168, 56, 101};
static const char NODE02_IPADDR[] = {192, 168, 56, 102};
static const int PACKET_PORT = 1234;

static const int MAX_TIMESTAMPS = 1 << 20;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, MAX_TIMESTAMPS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_map_t1
SEC(".maps"),
xdp_map_t2 SEC (
".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 4);
} indices
SEC(".maps");

static inline int swap (void *a, void *b, const int size, const void *packet_end)
{
    const void *end = b + size;
    if (end > packet_end)
        return -1;

    __u8 tmp;
    while (b < end)
        {
            tmp = *(__u8 *) a;
            *(__u8 *) a = *(__u8 *) b;
            *(__u8 *) b = tmp;
            ++a;
            ++b;
        }
    return 0;
}

static inline __u64
get_timestamp ()
{
    return bpf_ktime_get_ns ();
}

/**
 * Set a timestamp in the stats struct
 *
 * @param kind The number of timestamp (1,2,3,4)
 */
static __u32 set_timestamp (__u32 kind, __u64 timestamp)
{
    --kind;

    void *map = NULL;
    switch (kind)
        {
            case 0:
                map = &xdp_map_t1;
            break;
            case 1:
                map = &xdp_map_t2;
            break;
            default:
                return -1;
        }

    if (!map) return -1;

    __u32 *current_idx_ptr = (__u32 *) bpf_map_lookup_elem (&indices, &kind);
    if (current_idx_ptr == NULL) return -1;

    __u32 current_idx = *current_idx_ptr;

    if (current_idx >= MAX_TIMESTAMPS) return -1;

    bpf_map_update_elem (map, &current_idx, &timestamp, BPF_ANY);

    ++current_idx;
    bpf_map_update_elem (&indices, &kind, &current_idx, BPF_ANY);
    return 0;
}

static inline struct ethhdr *parse_ethhdr (void *data, void *data_end)
{
    if (data + sizeof (struct ethhdr) > data_end)
        return NULL;
    return (struct ethhdr *) data;
}

static inline struct iphdr *parse_iphdr (void *data, void *data_end)
{
    void *ip_start = data + sizeof (struct ethhdr);
    if (ip_start + sizeof (struct iphdr) > data_end)
        return NULL;
    return (struct iphdr *) ip_start;
}

static inline struct udphdr *parse_udphdr (void *data, void *data_end)
{
    void *udp_start = data + sizeof (struct ethhdr) + sizeof (struct iphdr);
    if (udp_start + sizeof (struct udphdr) > data_end)
        return NULL;
    return (struct udphdr *) udp_start;
}

static inline __u8
is_valid_ip_packet (struct iphdr *ip)
{
    return (ip->saddr == *((__be32 *) NODE01_IPADDR) && ip->daddr == *((__be32 *) NODE02_IPADDR))
           || (ip->saddr == *((__be32 *) NODE02_IPADDR) && ip->daddr == *((__be32 *) NODE01_IPADDR));
}

SEC (
"xdp_pp")
int xdp_prog (struct xdp_md *ctx)
{
    __u64 arrival_timestamp = get_timestamp ();

    void *data_end = (void *) (long) ctx->data_end;
    void *data = (void *) (long) ctx->data;

    struct ethhdr *eth = parse_ethhdr (data, data_end);
    if (!eth)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons (ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = parse_iphdr (data, data_end);
    if (!ip)
        return XDP_PASS;

    struct udphdr *udp = parse_udphdr (data, data_end);
    if (!udp)
        return XDP_PASS;

    if (is_valid_ip_packet (ip) == 0)
        return XDP_PASS;

    if (udp->dest == bpf_htons (PACKET_PORT))
        {
            if (set_timestamp (1, arrival_timestamp) < 0)
                {
                    return XDP_PASS;
                }
        }
    else
        {
            udp->dest = bpf_htons (PACKET_PORT);
        }

    swap (&eth->h_source, &eth->h_dest, sizeof (eth->h_source), data_end);
    swap (&ip->saddr, &ip->daddr, sizeof (ip->saddr), data_end);
    ip->check = 0;

    bpf_printk("Sending packet back");

    set_timestamp (2, get_timestamp ());
    return XDP_TX;
}

char _license[]
SEC("license") = "GPL";
