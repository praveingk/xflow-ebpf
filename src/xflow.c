/* SPDX-License-Identifier: GPL-2->0 */
#include <linux/bpf.h>
#include <linux/in.h>

#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
//#include <iproute2/bpf_elf.h>


#include "../common/parsing_helpers.h"
#include "../common/common_defines.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

#define MYNAME "xflow"

#define MAX_ENTRIES 1000
// struct bpf_map_def SEC("maps") xflow_map = {
// 	 .type        = BPF_MAP_TYPE_HASH,	
// 	 .key_size    = sizeof(flow_id),
// 	.value_size  = sizeof(flow_counters),
// 	.max_entries = MAX_ENTRIES,
// };

struct {
	__uint(type, BPF_MAP_TYPE_HASH);	
	__type(key, flow_id);
	__type(value, flow_counters);
    __uint(max_entries, MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xflow_map SEC(".maps");

SEC("xflow")
int xflow_start(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct hdr_cursor nh;
    nh.pos = data;
    int action = XDP_PASS;

    /* Get Flow ID : <sourceip, destip, sourceport, destport, protocol> */

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        bpf_printk(MYNAME
                   " Dropping received packet that did not"
                   " contain full Ethernet header (data_end-data)=%d\n",
                   data_end - data);
        action = XDP_DROP;
        goto out;
    }
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        // Non-IP packets
        goto out;
    }
    bpf_printk(MYNAME "-record\n");
    out:
        return xdp_stats_record_action(ctx, action);
}


char _license[] SEC("license") = "GPL";
