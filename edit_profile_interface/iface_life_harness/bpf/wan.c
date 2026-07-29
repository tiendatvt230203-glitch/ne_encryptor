#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") wan_xsks_map = {
    .type = BPF_MAP_TYPE_XSKMAP,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 64,
};

SEC("xdp")
int xdp_wan_redirect_prog(struct xdp_md *ctx)
{
    __u32 qid = ctx->rx_queue_index;
    return bpf_redirect_map(&wan_xsks_map, qid, 0);
}

char _license[] SEC("license") = "GPL";
