#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_ARP_VAL 0x0806
#define ETH_P_NE_L2_ENC 0x104A

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} wan_xsks_map SEC(".maps");

/* xdp.frags: driver may deliver jumbo as multi-buffer */
SEC("xdp.frags")
int xdp_wan_redirect_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u32 q0 = 0;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_ARP_VAL))
        return XDP_PASS;

    /* L2 encrypt marker */
    if (eth->h_proto == bpf_htons(ETH_P_NE_L2_ENC))
        return bpf_redirect_map(&wan_xsks_map, q0, 0);

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;
        return bpf_redirect_map(&wan_xsks_map, q0, 0);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
