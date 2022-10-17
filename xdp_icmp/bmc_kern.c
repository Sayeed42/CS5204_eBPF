#define KBUILD_MODNAME "bmc"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include "bpf_helpers.h"

static inline u16 compute_ip_checksum(struct iphdr *ip)
{
    u32 csum = 0;
    u16 *next_ip_u16 = (u16 *)ip;

    ip->check = 0;

#pragma clang loop unroll(full)
    for (int i = 0; i < (sizeof(*ip) >> 1); i++) {
        csum += *next_ip_u16++;
    }

	return ~((csum & 0xffff) + (csum >> 16));
}

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

	// Exchanging source and destination info
	// Taken directly from bmc code, so should work

	// unsigned char tmp_mac[ETH_ALEN];
	// __be32 tmp_ip;

	// memcpy(tmp_mac, eth->h_source, ETH_ALEN);
	// memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	// memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

	// tmp_ip = ip->saddr;
	// ip->saddr = ip->daddr;
	// ip->daddr = tmp_ip;
	// ip->check = compute_ip_checksum(ip);

	// Changing the type and zeroing the csum for calculation
	// icmp->type = 0;
	// icmp->checksum = 0;

	// Testing: this hard-coded memory-access works
	// if (payload + 57 > data_end)
	// 	return XDP_PASS;
	// bpf_printk("%u %u %u", *(payload + 16), *(payload + 17), *(payload + 18));
	// bpf_printk("%u %u %u", *(payload + 19), *(payload + 20), *(payload + 21));
	// bpf_printk("%u %u %u", *(payload + 22), *(payload + 23), *(payload + 24));

	// Testing: This for loop gets rejected by the verifier
	int j = 0;
	for (unsigned int i = 0; payload + i + 1 <= data_end; i++){
		j += *(payload +i);
		// bpf_printk("%u", *(payload +i));
	}
	bpf_printk("%u %u %u", htons(icmp->un.echo.id), htons(icmp->un.echo.sequence), icmp->checksum);

	return XDP_PASS;
	// return XDP_TX;
}

// to test colisions: keys declinate0123456 and macallums0123456 have hash colision
char _license[] SEC("license") = "GPL";