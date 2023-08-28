/* SPDX-License-Identifier: GPL-2.0 */

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/resource.h>

#include <bpf/bpf.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

#define NUM_FRAMES         (1<<18)
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE      64
#define INVALID_UMEM_FRAME UINT64_MAX

#define EXIT_OK            0
#define EXIT_FAIL          1

const static char ETH_SOURCE_MAC[] = {0x08, 0x00, 0x27, 0xE1, 0x1A, 0x3A};
const static char ETH_DEST_MAC[] = {0x08, 0x00, 0x27, 0x17, 0x3E, 0x18};
const static char IPV4_SOURCE[] = {192, 168, 56, 101};
const static char IPV4_DEST[] = {192, 168, 56, 103};
const static __be16 UDP_PORT = 1234;

struct config {
    __u32 xdp_flags;
    __u32 xsk_bind_flags;
    __u32 xsk_if_queue;
    __u32 xsk_poll_mode;
    int32_t ifindex;
    char ifname[IF_NAMESIZE];
    char filename[256];
    char progname[256];
};
struct config cfg = {};

int xsk_map_fd;
bool custom_xsk = false;

struct xsk_umem_info {
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buffer;
};
struct xsk_socket_info {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;

    uint64_t umem_frame_addr[NUM_FRAMES];
    uint32_t umem_frame_free;

    uint32_t outstanding_tx;
};

static inline __u64
timestamp (void)
{
    struct timespec tp;
    clock_gettime (CLOCK_MONOTONIC, &tp);
    return tp.tv_sec * 1000000000ULL + tp.tv_nsec;
}

static inline __u32
xsk_ring_prod__free (struct xsk_ring_prod *r)
{
    r->cached_cons = *r->consumer + r->size;
    return r->cached_cons - r->cached_prod;
}

static bool global_exit;

static struct xsk_umem_info *configure_xsk_umem (void *buffer, uint64_t size)
{
    struct xsk_umem_info *umem;
    int ret;

    umem = calloc (1, sizeof (*umem));
    if (!umem)
        return NULL;

    ret = xsk_umem__create (&umem->umem, buffer, size, &umem->fq, &umem->cq,
                            NULL);
    if (ret)
        {
            errno = -ret;
            return NULL;
        }

    umem->buffer = buffer;
    return umem;
}

static uint64_t xsk_alloc_umem_frame (struct xsk_socket_info *xsk)
{
    uint64_t frame;
    if (xsk->umem_frame_free == 0)
        return INVALID_UMEM_FRAME;

    frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
    xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
    return frame;
}

static void xsk_free_umem_frame (struct xsk_socket_info *xsk, uint64_t frame)
{
    assert (xsk->umem_frame_free < NUM_FRAMES);

    xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

static uint64_t xsk_umem_free_frames (struct xsk_socket_info *xsk)
{
    return xsk->umem_frame_free;
}

static struct xsk_socket_info *xsk_configure_socket (struct config *cfg,
                                                     struct xsk_umem_info *umem)
{
    struct xsk_socket_config xsk_cfg;
    struct xsk_socket_info *xsk_info;
    uint32_t idx;
    int i;
    int ret;
    uint32_t prog_id;

    xsk_info = calloc (1, sizeof (*xsk_info));
    if (!xsk_info)
        {
            printf ("calloc failed\n");
            return NULL;
        }

    xsk_info->umem = umem;
    xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    xsk_cfg.xdp_flags = cfg->xdp_flags;
    xsk_cfg.bind_flags = cfg->xsk_bind_flags;
    //xsk_cfg.libbpf_flags = (custom_xsk) ? XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD : 0;
    xsk_cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
    ret = xsk_socket__create (&xsk_info->xsk, cfg->ifname,
                              cfg->xsk_if_queue, umem->umem, &xsk_info->rx,
                              &xsk_info->tx, &xsk_cfg);
    if (ret)
        {
            printf ("xsk_socket__create failed\n");
            goto error_exit;
        }

    if (custom_xsk)
        {
            ret = xsk_socket__update_xskmap (xsk_info->xsk, xsk_map_fd);
            if (ret)
                {
                    printf ("xsk_socket__update_xskmap failed\n");
                    goto error_exit;
                }
        }
    else
        {
            /* Getting the program ID must be after the xdp_socket__create() call */
            if (bpf_xdp_query_id (cfg->ifindex, cfg->xdp_flags, &prog_id))
                {
                    printf ("bpf_xdp_query_id failed\n");
                    goto error_exit;
                }
        }

    /* Initialize umem frame allocation */
    for (i = 0; i < NUM_FRAMES; i++)
        xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;

    xsk_info->umem_frame_free = NUM_FRAMES;

    /* Stuff the receive path with buffers, we assume we have enough */
    ret = xsk_ring_prod__reserve (&xsk_info->umem->fq,
                                  XSK_RING_PROD__DEFAULT_NUM_DESCS,
                                  &idx);

    if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
        {
            printf ("xsk_ring_prod__reserve failed\n");
            goto error_exit;
        }

    for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
        *xsk_ring_prod__fill_addr (&xsk_info->umem->fq, idx++) =
            xsk_alloc_umem_frame (xsk_info);

    xsk_ring_prod__submit (&xsk_info->umem->fq,
                           XSK_RING_PROD__DEFAULT_NUM_DESCS);

    return xsk_info;

    error_exit:
    errno = -ret;
    return NULL;
}

static void complete_tx (struct xsk_socket_info *xsk)
{
    unsigned int completed;
    uint32_t idx_cq;

    if (!xsk->outstanding_tx)
        return;

    sendto (xsk_socket__fd (xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

    /* Collect/free completed TX buffers */
    completed = xsk_ring_cons__peek (&xsk->umem->cq,
                                     XSK_RING_CONS__DEFAULT_NUM_DESCS,
                                     &idx_cq);

    if (completed > 0)
        {
            for (int i = 0; i < completed; i++)
                xsk_free_umem_frame (xsk,
                                     *xsk_ring_cons__comp_addr (&xsk->umem->cq,
                                                                idx_cq++));

            xsk_ring_cons__release (&xsk->umem->cq, completed);
            xsk->outstanding_tx -= completed < xsk->outstanding_tx ?
                                   completed : xsk->outstanding_tx;
        }
}

static bool heartbeat (struct xsk_socket_info *xsk_socket)
{
    // allocate a frame, fill it with some simple ethernet, ip and udp data and send it
    //printf("Start packet preparation: \t%llu\n", timestamp());
    // allocate a frame
    uint64_t addr = xsk_alloc_umem_frame (xsk_socket);
    if (addr == INVALID_UMEM_FRAME)
        {
            printf ("xsk_alloc_umem_frame failed\n");
            return false;
        }

    // fill it with some simple ethernet, ip and udp data
    uint8_t *pkt = xsk_umem__get_data (xsk_socket->umem->buffer, addr);
    struct ethhdr *eth = (struct ethhdr *) pkt;
    eth->h_proto = htons (ETH_P_IP);
    memcpy (eth->h_dest, ETH_DEST_MAC, ETH_ALEN);
    memcpy (eth->h_source, ETH_SOURCE_MAC, ETH_ALEN);

    struct iphdr *ip = (struct iphdr *) (eth + 1);
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons (sizeof (*ip) + sizeof (struct udphdr));
    ip->id = 0;
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;

    memcpy (&ip->daddr, IPV4_DEST, sizeof (ip->daddr));
    memcpy (&ip->saddr, IPV4_SOURCE, sizeof (ip->saddr));

    // printf("Ip source: %d, destination: %d\n", ip->saddr, ip->daddr);

    struct udphdr *udp = (struct udphdr *) (ip + 1);
    udp->source = htons (UDP_PORT);
    udp->dest = htons (UDP_PORT);
    udp->len = htons (sizeof (*udp));
    udp->check = 0;
    //printf("End packet preparation: \t%llu\n", timestamp());

    //printf("Start packet send: \t\t%llu\n", timestamp());
    // send it
    uint32_t tx_idx = 0;
    int ret = xsk_ring_prod__reserve (&xsk_socket->tx, 1, &tx_idx);
    if (ret != 1)
        {
            /* No more transmit slots, drop the packet */
            return false;
        }

    xsk_ring_prod__tx_desc (&xsk_socket->tx, tx_idx)->addr = addr;
    xsk_ring_prod__tx_desc (&xsk_socket->tx, tx_idx)->len = sizeof (*eth) + sizeof (*ip) + sizeof (*udp);
    xsk_ring_prod__submit (&xsk_socket->tx, 1);
    xsk_socket->outstanding_tx++;

    complete_tx (xsk_socket);
    //printf("End packet send: \t\t%llu\n", timestamp());
    return true;
}

void parse_config (void)
{
    strncpy (cfg.ifname, "eth1", sizeof (cfg.ifname));
    cfg.ifindex = if_nametoindex (cfg.ifname);
}

int main (int argc, char **argv)
{
    void *packet_buffer;
    uint64_t packet_buffer_size;
    DECLARE_LIBXDP_OPTS (xdp_program_opts, xdp_opts, 0);
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    struct xsk_umem_info *umem;
    struct xsk_socket_info *xsk_socket;

    parse_config ();

    /* Allow unlimited locking of memory, so all memory needed for packet
     * buffers can be locked.
     */
    if (setrlimit (RLIMIT_MEMLOCK, &rlim))
        {
            fprintf (stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
                     strerror (errno));
            exit (EXIT_FAILURE);
        }

    /* Allocate memory for NUM_FRAMES of the default XDP frame size */
    packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
    if (posix_memalign (&packet_buffer,
                        getpagesize (), /* PAGE_SIZE aligned */
                        packet_buffer_size))
        {
            fprintf (stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
                     strerror (errno));
            exit (EXIT_FAILURE);
        }

    /* Initialize shared packet_buffer for umem usage */
    umem = configure_xsk_umem (packet_buffer, packet_buffer_size);
    if (umem == NULL)
        {
            fprintf (stderr, "ERROR: Can't create umem \"%s\"\n",
                     strerror (errno));
            exit (EXIT_FAILURE);
        }

    /* Open and configure the AF_XDP (xsk) socket */
    xsk_socket = xsk_configure_socket (&cfg, umem);
    if (xsk_socket == NULL)
        {
            fprintf (stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n",
                     strerror (errno));
            exit (EXIT_FAILURE);
        }

    __u64 start = timestamp ();
    bool ret = true;
    int i = 0;
    for (; i < NUM_FRAMES && ret; ++i)
        ret = heartbeat (xsk_socket);
    __u64 end = timestamp ();

    printf("Executed %d times\n", i);
    printf("Diff: %llu\n", end - start);
    printf ("Average time: %llu\n", (end - start) / NUM_FRAMES);
    // heartbeat (xsk_socket);

    /* Cleanup */
    xsk_socket__delete (xsk_socket->xsk);
    xsk_umem__delete (umem->umem);
    return EXIT_OK;
}
