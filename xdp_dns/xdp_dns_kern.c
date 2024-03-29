/*
SPDX-License-Identifier: GPL-2.0-or-later

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330
*/
#define DEFAULT_ACTION XDP_PASS
#define KBUILD_MODNAME "xdp_dns"

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>

#include "common.h"

//Create different BPF map of type Hash table for DNS A Records
//Key is a dns_query struct, value is the associated IPv4 address
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct dns_query);
	__type(value, struct a_record);
	__uint(max_entries, 65536);
    __uint(pinning, 1);
} xdns_a_records SEC(".maps");

//Create different BPF map of type Hash table for DNS AAAA Records
//Key is a dns_query struct, value is the associated IPv6 address
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct dns_query);
	__type(value, struct aaaa_record);
	__uint(max_entries, 65536);
    __uint(pinning, 1);
} xdns_aaaa_records SEC(".maps");

static int parse_query(struct xdp_md *ctx, void *query_start, struct dns_query *q);
#ifdef EDNS
static inline int create_ar_response(struct ar_hdr *ar, char *dns_buffer, size_t *buf_size);
static inline int parse_ar(struct xdp_md *ctx, struct dns_hdr *dns_hdr, int query_length, struct ar_hdr *ar);
#endif
static inline void modify_dns_header_response(struct dns_hdr *dns_hdr);
static inline void update_ip_checksum(void *data, int len, uint16_t *checksum_location);
static inline void swap_mac(uint8_t *src_mac, uint8_t *dst_mac);

char dns_buffer[40];

SEC("xdp")
int xdp_dns(struct xdp_md *ctx)
{
    #ifdef DEBUG
    uint64_t start = bpf_ktime_get_ns();
    #endif

    void *data_end = (void *)(unsigned long)ctx->data_end;
    void *data = (void *)(unsigned long)ctx->data;

    //Boundary check: check if packet is larger than a full ethernet + ip header
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
    {
        return DEFAULT_ACTION;
    }

    struct ethhdr *eth = data;

    //Ignore packet if ethernet protocol is not IP-based
    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        return DEFAULT_ACTION;
    }

    struct iphdr *ip = data + sizeof(*eth);

    if (ip->protocol == IPPROTO_UDP)
    {
        struct udphdr *udp;
        //Boundary check for UDP
        if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
        {
            return DEFAULT_ACTION;
        }

        udp = data + sizeof(*eth) + sizeof(*ip);

        //Check if dest port equals 53
        if (udp->dest == bpf_htons(53))
        {
            #ifdef DEBUG
            bpf_printk("Packet dest port 53");
            bpf_printk("Data pointer starts at %u", data);
            #endif

            //Boundary check for minimal DNS header
            if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(struct dns_hdr) > data_end)
            {
                return DEFAULT_ACTION;
            }

            struct dns_hdr *dns_hdr = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);

            //Check if header contains a standard query
            if (dns_hdr->qr == 0 && dns_hdr->opcode == 0)
            {
                #ifdef DEBUG
                bpf_printk("DNS query transaction id %u", bpf_ntohs(dns_hdr->transaction_id));
                #endif

                //Get a pointer to the start of the DNS query
                void *query_start = (void *)dns_hdr + sizeof(struct dns_hdr);

                //We will only be parsing a single query for now
                struct dns_query q;
                int query_length = 0;
                query_length = parse_query(ctx, query_start, &q);
                if (query_length < 1)
                {
                    return DEFAULT_ACTION;
                }

                size_t buf_size = 0;
                #ifdef DEBUG
                bpf_printk("DNS record type: %i", q.record_type);
                bpf_printk("DNS class: %i", q.class);
                bpf_printk("DNS name: %s", q.name);
                #endif

                if (q.record_type == A_RECORD_TYPE) {
                    //Check if query matches a record in our hash table
                    struct a_record *a_record;
                    a_record = bpf_map_lookup_elem(&xdns_a_records, &q);
                    if (!a_record) {
                        return DEFAULT_ACTION;
                    }

                    buf_size = sizeof(struct dns_response);
                    //Create DNS response and add to temporary buffer.
                    //Formulate a DNS response. Currently defaults to hardcoded query pointer + type + class in + ttl + ip_addr as reply.
                    struct dns_response *response = (struct dns_response *) &dns_buffer[0];
                    response->query_pointer = bpf_htons(0xc00c);
                    response->class = bpf_htons(0x0001);
                    response->record_type = bpf_htons(A_RECORD_TYPE);
                    response->ttl = bpf_htonl(a_record->ttl);
                    response->data_length = bpf_htons((uint16_t)sizeof(a_record->ip_addr));
                    //Copy IP address
                    __builtin_memcpy(&dns_buffer[buf_size], &a_record->ip_addr, sizeof(struct in_addr));
                    buf_size += sizeof(struct in_addr);
                } else if (q.record_type == AAAA_RECORD_TYPE) {
                    //Check if query matches a record in our hash table
                    struct aaaa_record *aaaa_record;
                    aaaa_record = bpf_map_lookup_elem(&xdns_aaaa_records, &q);
                    if (!aaaa_record) {
                        return DEFAULT_ACTION;
                    }

                    buf_size = sizeof(struct dns_response);
                    struct dns_response *response = (struct dns_response *) &dns_buffer[0];
                    response->query_pointer = bpf_htons(0xc00c);
                    response->class = bpf_htons(0x0001);
                    response->record_type = bpf_htons(AAAA_RECORD_TYPE);
                    response->ttl = bpf_htonl(aaaa_record->ttl);
                    response->data_length = bpf_htons((uint16_t)sizeof(aaaa_record->ip_addr));
                    //Copy IP address
                    __builtin_memcpy(&dns_buffer[buf_size], &aaaa_record->ip_addr, sizeof(struct in6_addr));
                    buf_size += sizeof(struct in6_addr);
                } else {
                    return DEFAULT_ACTION;
                }
                
                //Change DNS header to a valid response header
                modify_dns_header_response(dns_hdr);

                #ifdef EDNS
                //If an additional record is present
                if(dns_hdr->add_count > 0)
                {
                    //Parse AR record
                    struct ar_hdr ar;
                    if(parse_ar(ctx, dns_hdr, query_length, &ar) != -1)
                    {     
                        //Create AR response and add to temporary buffer
                        create_ar_response(&ar, &dns_buffer[buf_size], &buf_size);
                    }
                }
                #endif

                //Start our response [query_length] bytes beyond the header
                void *answer_start = (void *)dns_hdr + sizeof(struct dns_hdr) + query_length;
                //Determine increment of packet buffer
                int tailadjust = answer_start + buf_size - data_end;

                //Adjust packet length accordingly
                if (bpf_xdp_adjust_tail(ctx, tailadjust))
                {
                    #ifdef DEBUG
                    bpf_printk("Adjust tail fail");
                    #endif
                }
                else
                {
                    //Because we adjusted packet length, mem addresses might be changed.
                    //Reinit pointers, as verifier will complain otherwise.
                    data = (void *)(unsigned long)ctx->data;
                    data_end = (void *)(unsigned long)ctx->data_end;

                    //Copy bytes from our temporary buffer to packet buffer
                    char *dst = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_hdr) + query_length;
                    for (int i = 0; i < sizeof(dns_buffer) && i < buf_size && dst + i + 1 <= data_end; i++) {
                        dst[i] = dns_buffer[i];
                    }
                    
                    eth = data;
                    ip = data + sizeof(struct ethhdr);
                    udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

                    //Do a new boundary check
                    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
                    {
                        #ifdef DEBUG
                        bpf_printk("Error: Boundary exceeded");
                        #endif
                        return DEFAULT_ACTION;
                    }

                    //Adjust UDP length and IP length
                    uint16_t iplen = (data_end - data) - sizeof(struct ethhdr);
                    uint16_t udplen = (data_end - data) - sizeof(struct ethhdr) - sizeof(struct iphdr);
                    ip->tot_len = bpf_htons(iplen);
                    udp->len = bpf_htons(udplen);

                    //Swap eth macs
                    swap_mac((uint8_t *)eth->h_source, (uint8_t *)eth->h_dest);

                    //Swap src/dst IP
                    uint32_t src_ip = ip->saddr;
                    ip->saddr = ip->daddr;
                    ip->daddr = src_ip;

                    //Set UDP checksum to zero
                    udp->check = 0;

                    //Swap udp src/dst ports
                    uint16_t tmp_src = udp->source;
                    udp->source = udp->dest;
                    udp->dest = tmp_src;

                    //Recalculate IP checksum
                    update_ip_checksum(ip, sizeof(struct iphdr), &ip->check);

                    #ifdef DEBUG
                    bpf_printk("XDP_TX");
                    #endif

        
                    #ifdef DEBUG
                    uint64_t end = bpf_ktime_get_ns();
                    uint64_t elapsed = end-start;
                    bpf_printk("Time elapsed: %d", elapsed);
                    #endif

                    //Emit modified packet
                    return XDP_TX;
                }
            }
        }
    }

    return DEFAULT_ACTION;
}

//Parse query and return query length
static int parse_query(struct xdp_md *ctx, void *query_start, struct dns_query *q)
{
    void *data_end = (void *)(long)ctx->data_end;

    #ifdef DEBUG
    bpf_printk("Parsing query");
    #endif

    uint16_t i;
    void *cursor = query_start;
    int namepos = 0;

    //Fill dns_query.name with zero bytes
    //Not doing so will make the verifier complain when dns_query is used as a key in bpf_map_lookup
    memset(&q->name[0], 0, sizeof(q->name));
    //Fill record_type and class with default values to satisfy verifier
    q->record_type = 0;
    q->class = 0;

    //We create a bounded loop of MAX_DNS_NAME_LENGTH (maximum allowed dns name size).
    //We'll loop through the packet byte by byte until we reach '0' in order to get the dns query name
    for (i = 0; i < MAX_DNS_NAME_LENGTH; i++)
    {

        //Boundary check of cursor. Verifier requires a +1 here. 
        //because data is contained up to data_end
        if (cursor + 1 > data_end)
        {
            #ifdef DEBUG
            bpf_printk("Error: boundary exceeded while parsing DNS query name");
            #endif
            break;
        }

        //If separator is zero we've reached the end of the domain query
        if (*(char *)(cursor) == 0)
        {

            //We've reached the end of the query name.
            //This will be followed by 2x 2 bytes: the dns type and dns class.
            if (cursor + 5 > data_end)
            {
                #ifdef DEBUG
                bpf_printk("Error: boundary exceeded while retrieving DNS record type and class");
                #endif
            }
            else
            {
                q->record_type = bpf_htons(*(uint16_t *)(cursor + 1));
                q->class = bpf_htons(*(uint16_t *)(cursor + 3));
            }

            //Return the bytecount of (namepos + current '0' byte + dns type + dns class) as the query length.
            return namepos + 1 + 2 + 2;
        }

        //Read and fill data into struct
        q->name[namepos] = *(char *)(cursor);
        namepos++;
        cursor++;
    }

    return -1;
}


#ifdef EDNS
//Parse additonal record
static inline int parse_ar(struct xdp_md *ctx, struct dns_hdr *dns_hdr, int query_length, struct ar_hdr *ar)
{
    #ifdef DEBUG
    bpf_printk("Parsing additional record in query");
    #endif

    void *data_end = (void *)(long)ctx->data_end;

    //Parse ar record
    ar  = (void *) dns_hdr + query_length + sizeof(struct dns_response);
    if((void*) ar + sizeof(struct ar_hdr) > data_end){
        #ifdef DEBUG
        bpf_printk("Error: boundary exceeded while parsing additional record");
        #endif
        return -1;
    }

    return 0;
}

static inline int create_ar_response(struct ar_hdr *ar, char *dns_buffer, size_t *buf_size)
{
    //Check for OPT record (RFC6891)
    if(ar->type == bpf_htons(41)){
        #ifdef DEBUG
        bpf_printk("OPT record found");
        #endif
        struct ar_hdr *ar_response = (struct ar_hdr *) &dns_buffer[0];
        //We've received an OPT record, advertising the clients' UDP payload size
        //Respond that we're serving a payload size of 512 and not serving any additional records.
        ar_response->name = 0;
        ar_response->type = bpf_htons(41);
        ar_response->size = bpf_htons(512);
        ar_response->ex_rcode = 0;
        ar_response->rcode_len = 0;

        *buf_size += sizeof(struct ar_hdr);
    }
    else
    {
        return -1;
    }
        
    return 0;
}
#endif

//Update IP checksum for IP header, as specified in RFC 1071
//The checksum_location is passed as a pointer. At this location 16 bits need to be set to 0.
static inline void update_ip_checksum(void *data, int len, uint16_t *checksum_location)
{
    uint32_t accumulator = 0;
    int i;
    for (i = 0; i < len; i += 2)
    {
        uint16_t val;
        //If we are currently at the checksum_location, set to zero
        if (data + i == checksum_location)
        {
            val = 0;
        }
        else
        {
            //Else we load two bytes of data into val
            val = *(uint16_t *)(data + i);
        }
        accumulator += val;
    }

    //Add 16 bits overflow back to accumulator (if necessary)
    uint16_t overflow = accumulator >> 16;
    accumulator &= 0x00FFFF;
    accumulator += overflow;

    //If this resulted in an overflow again, do the same (if necessary)
    accumulator += (accumulator >> 16);
    accumulator &= 0x00FFFF;

    //Invert bits and set the checksum at checksum_location
    uint16_t chk = accumulator ^ 0xFFFF;

    #ifdef DEBUG
    bpf_printk("Checksum: %u", chk);
    #endif

    *checksum_location = chk;
}

static inline void modify_dns_header_response(struct dns_hdr *dns_hdr)
{
    //Set query response
    dns_hdr->qr = 1;
    //Set truncated to 0
    //dns_hdr->tc = 0;
    //Set authorative to zero
    //dns_hdr->aa = 0;
    //Recursion available
    dns_hdr->ra = 1;
    //One answer
    dns_hdr->ans_count = bpf_htons(1);
}

static inline void swap_mac(uint8_t *src_mac, uint8_t *dst_mac)
{
    int i;
    for (i = 0; i < 6; i++)
    {
        uint8_t tmp_src;
        tmp_src = *(src_mac + i);
        *(src_mac + i) = *(dst_mac + i);
        *(dst_mac + i) = tmp_src;
    }
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = LINUX_VERSION_CODE;
