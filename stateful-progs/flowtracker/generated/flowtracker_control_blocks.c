/* Automatically generated by p4c-pna-p4tc from flowtracker.p4 on Mon Dec  4 22:28:11 2023
 */

#include "flowtracker_parser.h"
#include <stdbool.h>
#include <linux/if_ether.h>
#include "pna.h"
struct internal_metadata {
    __u16 pkt_ether_type;
} __attribute__((aligned(4)));


struct __attribute__((__packed__)) Main_ct_flow_table_key {
    u32 keysz;
    u32 maskid;
    u32 field0; /* istd.input_port */
    u32 field1; /* hdr.ipv4.srcAddr */
    u32 field2; /* hdr.ipv4.dstAddr */
    u8 field3; /* hdr.ipv4.protocol */
    u16 field4; /* meta.srcPort */
    u16 field5; /* meta.dstPort */
} __attribute__((aligned(8)));
#define MAIN_CT_FLOW_TABLE_ACT_MAIN_CT_FLOW_MISS 1
#define MAIN_CT_FLOW_TABLE_ACT_MAIN_CT_FLOW_HIT 2
struct __attribute__((__packed__)) Main_ct_flow_table_value {
    unsigned int action;
    __u32 hit:1,
           is_default_miss_act:1,
           is_default_hit_act:1;
    union {
        struct {
        } _NoAction;
        struct {
            u32 param1;
        } Main_ct_flow_miss;
        struct {
        } Main_ct_flow_hit;
    } u;
};

REGISTER_START()
REGISTER_TABLE(hdr_md_cpumap, BPF_MAP_TYPE_PERCPU_ARRAY, u32, struct hdr_md, 2)
BPF_ANNOTATE_KV_PAIR(hdr_md_cpumap, u32, struct hdr_md)
REGISTER_END()

struct p4tc_filter_fields {
        __u32 pipeid;
        __u32 handle;
        __u32 classid;
	__u32 chain;
	__u32 blockid;
        __be16 proto;
        __u16 prio;
};
struct p4tc_filter_fields p4tc_filter_fields;

static __always_inline int process(struct __sk_buff *skb, struct headers_t *hdr, struct pna_global_metadata *compiler_meta__)
{
    struct hdr_md *hdrMd;
    unsigned ebpf_packetOffsetInBits = hdrMd->ebpf_packetOffsetInBits;
    const __u32 pipeid = p4tc_filter_fields.pipeid;
    ParserError_t ebpf_errorCode = NoError;
    void* pkt = ((void*)(long)skb->data);
    void* ebpf_packetEnd = ((void*)(long)skb->data_end);
    u32 ebpf_zero = 0;
    u32 ebpf_one = 1;
    unsigned char ebpf_byte;
    u32 pkt_len = skb->len;

    struct my_ingress_metadata_t *meta;
    hdrMd = BPF_MAP_LOOKUP_ELEM(hdr_md_cpumap, &ebpf_zero);
    if (!hdrMd)
        return TC_ACT_SHOT;
    hdr = &(hdrMd->cpumap_hdr);
    meta = &(hdrMd->cpumap_usermeta);
{
        u8 hit;
        {
if (/* hdr->tcp.isValid() */
            hdr->tcp.ebpf_valid) {
                meta->srcPort = bpf_htons(hdr->tcp.srcPort);
                meta->dstPort = bpf_htons(hdr->tcp.dstPort);
            }
            else {
if (/* hdr->udp.isValid() */
                hdr->udp.ebpf_valid) {
                    meta->srcPort = bpf_htons(hdr->udp.srcPort);
                    meta->dstPort = bpf_htons(hdr->udp.dstPort);
                }
            }

            /* ct_flow_table_0.apply() */
            {
                /* construct key */
                struct p4tc_table_entry_act_bpf_params__local params = {
                    .pipeid = pipeid,
                    .tblid = 1
                };
                struct Main_ct_flow_table_key key;
                __builtin_memset(&key, 0, sizeof(key));
                key.keysz = 136;
                key.field0 = skb->ifindex;
                key.field1 = hdr->ipv4.srcAddr;
                key.field2 = hdr->ipv4.dstAddr;
                key.field3 = hdr->ipv4.protocol;
                key.field4 = meta->srcPort;
                key.field5 = meta->dstPort;
                struct p4tc_table_entry_act_bpf *act_bpf;
                /* value */
                struct Main_ct_flow_table_value *value = NULL;
                /* perform lookup */
                act_bpf = bpf_p4tc_tbl_read(skb, &params, sizeof(params), &key,
					    sizeof(key));
                value = (struct Main_ct_flow_table_value *)act_bpf;
                if (value == NULL) {
                    /* miss; find default action */
                    hit = 0;
                } else {
                    hit = value->hit;
                }
                if (value != NULL) {
                    /* run action */
                    switch (value->action) {
                        case 0:
                            break;
                        case MAIN_CT_FLOW_TABLE_ACT_MAIN_CT_FLOW_MISS:
                            {
			        struct p4tc_table_entry_create_bpf_params__local create_params = {
				.pipeid = pipeid,
				.tblid = 1
			        };

				create_params.handle = p4tc_filter_fields.handle;
				create_params.classid = p4tc_filter_fields.classid;
				create_params.proto = p4tc_filter_fields.proto;
				create_params.prio = p4tc_filter_fields.prio;
				create_params.chain = p4tc_filter_fields.chain;
                                bpf_p4tc_entry_create(skb, &create_params, sizeof(create_params),
						      &key, sizeof(key));
                            }
                            break;
                        default:
                            return TC_ACT_SHOT;
                    }
                } else {
                    return TC_ACT_SHOT;
;
                }
            }
;
        }
    }
    {
{
;
            ;
            ;
            ;
        }

        if (compiler_meta__->drop) {
            return TC_ACT_SHOT;
        }

        pkt = ((void*)(long)skb->data);
        ebpf_packetEnd = ((void*)(long)skb->data_end);
        ebpf_packetOffsetInBits = 0;
        if (hdr->eth.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 112)) {
                return TC_ACT_SHOT;
            }

            hdr->eth.dstAddr = htonll(hdr->eth.dstAddr << 16);
            ebpf_byte = ((char*)(&hdr->eth.dstAddr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->eth.dstAddr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->eth.dstAddr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->eth.dstAddr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->eth.dstAddr))[4];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 4, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->eth.dstAddr))[5];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 5, (ebpf_byte));
            ebpf_packetOffsetInBits += 48;

            hdr->eth.srcAddr = htonll(hdr->eth.srcAddr << 16);
            ebpf_byte = ((char*)(&hdr->eth.srcAddr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->eth.srcAddr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->eth.srcAddr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->eth.srcAddr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->eth.srcAddr))[4];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 4, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->eth.srcAddr))[5];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 5, (ebpf_byte));
            ebpf_packetOffsetInBits += 48;

            hdr->eth.etherType = bpf_htons(hdr->eth.etherType);
            ebpf_byte = ((char*)(&hdr->eth.etherType))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->eth.etherType))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

        }
;        if (hdr->ipv4.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 160)) {
                return TC_ACT_SHOT;
            }

            ebpf_byte = ((char*)(&hdr->ipv4.version))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 4, 4, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 4;

            ebpf_byte = ((char*)(&hdr->ipv4.ihl))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 4, 0, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 4;

            ebpf_byte = ((char*)(&hdr->ipv4.diffserv))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_packetOffsetInBits += 8;

            hdr->ipv4.totalLen = bpf_htons(hdr->ipv4.totalLen);
            ebpf_byte = ((char*)(&hdr->ipv4.totalLen))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv4.totalLen))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            hdr->ipv4.identification = bpf_htons(hdr->ipv4.identification);
            ebpf_byte = ((char*)(&hdr->ipv4.identification))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv4.identification))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            ebpf_byte = ((char*)(&hdr->ipv4.flags))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 3, 5, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 3;

            hdr->ipv4.fragOffset = bpf_htons(hdr->ipv4.fragOffset << 3);
            ebpf_byte = ((char*)(&hdr->ipv4.fragOffset))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 5, 0, (ebpf_byte >> 3));
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0 + 1, 3, 5, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv4.fragOffset))[1];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 1, 5, 0, (ebpf_byte >> 3));
            ebpf_packetOffsetInBits += 13;

            ebpf_byte = ((char*)(&hdr->ipv4.ttl))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_packetOffsetInBits += 8;

            ebpf_byte = ((char*)(&hdr->ipv4.protocol))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_packetOffsetInBits += 8;

            hdr->ipv4.hdrChecksum = bpf_htons(hdr->ipv4.hdrChecksum);
            ebpf_byte = ((char*)(&hdr->ipv4.hdrChecksum))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv4.hdrChecksum))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            ebpf_byte = ((char*)(&hdr->ipv4.srcAddr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv4.srcAddr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv4.srcAddr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv4.srcAddr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_packetOffsetInBits += 32;

            ebpf_byte = ((char*)(&hdr->ipv4.dstAddr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv4.dstAddr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv4.dstAddr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv4.dstAddr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_packetOffsetInBits += 32;

        }
;        if (hdr->tcp.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 32)) {
                return TC_ACT_SHOT;
            }

            hdr->tcp.srcPort = bpf_htons(hdr->tcp.srcPort);
            ebpf_byte = ((char*)(&hdr->tcp.srcPort))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->tcp.srcPort))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            hdr->tcp.dstPort = bpf_htons(hdr->tcp.dstPort);
            ebpf_byte = ((char*)(&hdr->tcp.dstPort))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->tcp.dstPort))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

        }
;
    }
    return -1;
}
SEC("p4tc/main")
int tc_ingress_func(struct __sk_buff *skb) {
    struct pna_global_metadata *compiler_meta__ = (struct pna_global_metadata *) skb->cb;
    if (!compiler_meta__->recirculated) {
        compiler_meta__->mark = 153;
        struct internal_metadata *md = (struct internal_metadata *)(unsigned long)skb->data_meta;
        if ((void *) ((struct internal_metadata *) md + 1) <= (void *)(long)skb->data) {
            __u16 *ether_type = (__u16 *) ((void *) (long)skb->data + 12);
            if ((void *) ((__u16 *) ether_type + 1) > (void *) (long) skb->data_end) {
                return TC_ACT_SHOT;
            }
            *ether_type = md->pkt_ether_type;
        }
    }
    struct hdr_md *hdrMd;
    struct headers_t *hdr;
    int ret = -1;

    ret = process(skb, (struct headers_t *) hdr, compiler_meta__);
    if (ret != -1) {
        return ret;
    }
    if (!compiler_meta__->drop && compiler_meta__->egress_port == 0)
	    return TC_ACT_OK;
    return bpf_redirect(compiler_meta__->egress_port, 0);
}
char _license[] SEC("license") = "GPL";
