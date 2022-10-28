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
	struct icmphdr *icmp;
	char *payload;

	if (ip + 1 > data_end)
		return XDP_PASS;

	switch (ip->protocol) {
		case IPPROTO_ICMP:
			icmp = (struct icmphdr *) transp;
			if (icmp + 1 > data_end)
				return XDP_PASS;
			payload = transp + sizeof(*icmp);
			break;
		default:
			return XDP_PASS;
	}

	unsigned char tmp_mac[ETH_ALEN];
	__be32 tmp_ip;

	memcpy(tmp_mac, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

	tmp_ip = ip->saddr;
	ip->saddr = ip->daddr;
	ip->daddr = tmp_ip;
	// ip->check = compute_ip_checksum(ip);

	icmp->type = 0;
	u16 csum = htons(icmp->checksum);
	csum += 0x0800;
	icmp->checksum = ntohs(csum);
	bpf_printk("Passing through XDP");
	return XDP_TX;
}

char _license[] SEC("license") = "GPL";