/**
 * lb = latency buckets
 * Pingpong XDP hooks that collect latency stats
 * into discrete "buckets" = ranges, counting how many
 * occurences end up in each bucket. 
*/
#include <linux/bpf.h>
#include <linux/time.h>
#include <linux/in.h>
#include <linux/ptrace.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/ethtool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// #ifndef lock_xadd
// #define lock_xadd(ptr, val) ((void)__sync_fetch_and_add(ptr, val))
// #endif

// #ifndef lock_fetch
// #define lock_fetch(ptr) ((void)__sync_fetch_and_add(ptr, 0))
// #endif

// ip check disabled
static const char NODE01_IPADDR[] = {};
static const char NODE02_IPADDR[] = {};
// port check only
static const int PACKET_PORT = 1234;
static const int PAYLOAD_OFFSET = 0;
static const int WARMUP_ROUNDS = 10;

static const long CLOCK_SPEED = 2400000000; // 2.4 GHz
static const int BUCKETS = 10000; // number of buckets
static const int BUCKET_SIZE_NS = 100; // granularity
// total range is from 0 to BUCKETS*BUCKET_SIZE_NS nanoseconds

/**
 * Packet structure:
 * ,--------------------------------------------------------,
 * | ethhdr | iphdr | udphdr | id | round | ts1 | ts2 | ts3 |
 * '--------------------------------------------------------'
 * id = 0 -> PING
 * id = 1 -> PONG
 */
#pragma pack(push, 2) // avoid struct padding
struct pp_payload
{
    __u16 id;
    __u64 round;
    __u64 ts1;
    __u64 ts2;
    __u64 ts3;
};
#pragma pack(pop)

// MAPS
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, BUCKETS + 1); // extra bucket for out of range data
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} latency_buckets
SEC(".maps");

static const int total_key = 0;
static const int min_key = 1;
static const int max_key = 2;
static const int avg_key = 3;
static const int zerocount_key = 4;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 5);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} latency_global_stats
SEC(".maps");

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
 * Compute the latency and update the stats
 *
 * @param payload pointer to the current packet payload
 * @param ts4 last received timestamp
 */
static __u32 update_maps(struct pp_payload *payload, __u64 ts4)
{
    if (payload->round < WARMUP_ROUNDS)
        return 0;

    // udpate buckets stats: compute latency and increase counter
    // of its corresponding bucket
    __u64 latency_ns = ((ts4 - payload->ts1) - (payload->ts3 - payload->ts2))/2 
                        * 1000000000 / CLOCK_SPEED; // assume GHz
                        
    if (latency_ns == 0){
        // update zero count
        __u64 *count = (__u64 *) bpf_map_lookup_elem(&latency_global_stats, &zerocount_key);
            if (!count) {
               __u64 initval = 1;
                bpf_map_update_elem(&latency_global_stats, &zerocount_key, &initval, BPF_ANY);
        }
        else {
            (*count)++;
        }
        return 1;
    }

    __u32 bucket_number = latency_ns / BUCKET_SIZE_NS;
    if (bucket_number > BUCKETS) {
        bucket_number = BUCKETS;
    }
    bpf_printk("lat: %llu, bucket 3: %lu", latency_ns, bucket_number);
    __u64 *count = (__u64 *) bpf_map_lookup_elem(&latency_buckets, &bucket_number);
    
    if (!count) {
        __u64 initval = 1;
        bpf_map_update_elem(&latency_buckets, &bucket_number, &initval, BPF_ANY);
    }
    else {
        (*count)++;
    }

    // udpate total packets (rounds)
    bpf_map_update_elem(&latency_global_stats, &total_key, &payload->round, BPF_ANY);
    // update min
    __u64 *min = (__u64 *) bpf_map_lookup_elem(&latency_global_stats, &min_key);
    if (!min || (*min) == 0 || latency_ns < *min) {
        bpf_map_update_elem(&latency_global_stats, &min_key, &latency_ns, BPF_ANY);
    }
     __u64 *max = (__u64 *) bpf_map_lookup_elem(&latency_global_stats, &max_key);
    if (!max || latency_ns > *max) {
        bpf_map_update_elem(&latency_global_stats, &max_key, &latency_ns, BPF_ANY);
    }
    // avg = (__u64) bpf_map_lookup_elem(&latency_global_stats, &avg_key);
    // if (!avg) {
    //     avg = 0;
    // }

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
                        sizeof(struct udphdr) + PAYLOAD_OFFSET;

    if (payload_ptr + sizeof(struct pp_payload) > data_end)
        return NULL;

    return (struct pp_payload *)payload_ptr;
}

SEC("xdp_pp")
int xdp_prog(struct xdp_md *ctx)
{
    __u64 arrival_timestamp = get_timestamp();

    //bpf_printk("recvd packet");

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

    // skip the IP check
    // if (is_valid_ip_packet(ip) == 0)
    //     return XDP_PASS;
    //bpf_printk("valid pkt\n");
    
    struct udphdr *udp = parse_udphdr(data, data_end);
    if (!udp)
        return XDP_PASS;

    if (udp->dest != bpf_htons(PACKET_PORT))
    {
        return XDP_PASS;
    }

    //bpf_printk("correct port, processing payload");

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
        payload->id = 1;
        payload->ts3 = get_timestamp();

        return XDP_TX;
    }
    else if (payload->id == 1)
    {
        // PONG
        update_maps(payload, arrival_timestamp);

        return XDP_DROP;
    }

    bpf_printk("unrecognised packet/packet ID");
    // print_hex_dump?

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";