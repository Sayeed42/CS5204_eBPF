#define KBUILD_MODNAME "bmc"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include "bpf_helpers.h"

SEC("xdp")
int icmp_serv(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(*eth);
	void *transp = data + sizeof(*eth) + sizeof(*ip);
	struct udphdr *udp;
	struct tcphdr *tcp;
	struct icmphdr *icmp;
	char *payload;
	__be16 dport;

	if (ip + 1 > data_end)
		return XDP_PASS;

	switch (ip->protocol) {
		case IPPROTO_ICMP:
			icmp = (struct icmphdr *) transp;
			if (icmp + 1 > data_end)
				return XDP_PASS;
			payload = transp + sizeof(*icmp);
			break;
		case IPPROTO_TCP:
			tcp = (struct tcphdr *) transp;
			if (tcp + 1 > data_end)
				return XDP_PASS;
			dport = tcp->dest;
			payload = transp + sizeof(*tcp);
			break;
		default:
			return XDP_PASS;
	}
	if (payload + 11 > data_end)
		return XDP_PASS;
	bpf_printk("Bytes: %u %u %u", *(payload + 8), *(payload + 9), *(payload + 10));

	return XDP_PASS;
}

// to test colisions: keys declinate0123456 and macallums0123456 have hash colision
char _license[] SEC("license") = "GPL";