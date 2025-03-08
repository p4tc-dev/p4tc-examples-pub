#include "flowtracker_ipv6_parser.h"
struct p4tc_filter_fields p4tc_filter_fields;

struct internal_metadata {
    __u16 pkt_ether_type;
} __attribute__((aligned(4)));

struct skb_aggregate {
    struct p4tc_skb_meta_get get;
    struct p4tc_skb_meta_set set;
};

struct __attribute__((__packed__)) Main_ct_flow_table_key {
    u32 keysz;
    u32 maskid;
    u32 field0; /* istd.input_port */
    u8 field1[16]; /* hdr.ipv6.srcAddr */
    u8 field2[16]; /* hdr.ipv6.dstAddr */
    u8 field3; /* hdr.ipv6.nextHdr */
    u16 field4; /* meta.srcPort */
    u16 field5; /* meta.dstPort */
} __attribute__((aligned(8)));
#define MAIN_CT_FLOW_TABLE_ACT__NOACTION 0
#define MAIN_CT_FLOW_TABLE_ACT_MAIN_CT_FLOW_MISS 1
struct __attribute__((__packed__)) Main_ct_flow_table_value {
    unsigned int action;
    u32 hit:1,
    is_default_miss_act:1,
    is_default_hit_act:1;
    union {
        struct {
        } _NoAction;
        struct {
        } Main_ct_flow_miss;
    } u;
};

static __always_inline int process(struct __sk_buff *skb, struct headers_t *hdr, struct pna_global_metadata *compiler_meta__, struct skb_aggregate *sa)
{
    struct hdr_md *hdrMd;

    unsigned ebpf_packetOffsetInBits_save = 0;
    ParserError_t ebpf_errorCode = NoError;
    void* pkt = ((void*)(long)skb->data);
    u8* hdr_start = pkt;
    void* ebpf_packetEnd = ((void*)(long)skb->data_end);
    u32 ebpf_zero = 0;
    u32 ebpf_one = 1;
    unsigned char ebpf_byte;
    u32 pkt_len = skb->len;

    struct my_ingress_metadata_t *meta;
    hdrMd = BPF_MAP_LOOKUP_ELEM(hdr_md_cpumap, &ebpf_zero);
    if (!hdrMd)
        return TC_ACT_SHOT;
    unsigned ebpf_packetOffsetInBits = hdrMd->ebpf_packetOffsetInBits;
    hdr_start = pkt + BYTES(ebpf_packetOffsetInBits);
    hdr = &(hdrMd->cpumap_hdr);
    meta = &(hdrMd->cpumap_usermeta);
{
        u8 hit;
        {
if (/* hdr->tcp.isValid() */
            hdr->tcp.ebpf_valid) {
                meta->srcPort = hdr->tcp.srcPort;
                                meta->dstPort = hdr->tcp.dstPort;
            }
            else {
if (/* hdr->udp.isValid() */
                hdr->udp.ebpf_valid) {
                    meta->srcPort = hdr->udp.srcPort;
                                        meta->dstPort = hdr->udp.dstPort;
                }            }

            /* ct_flow_table_0.apply() */
            {
                /* construct key */
                struct p4tc_table_entry_act_bpf_params__local params = {
                    .pipeid = p4tc_filter_fields.pipeid,
                    .tblid = 1
                };
                struct Main_ct_flow_table_key key;
                __builtin_memset(&key, 0, sizeof(key));
                key.keysz = 328;
                key.field0 = skb->ifindex;
                __builtin_memcpy(&(key.field1), &(hdr->ipv6.srcAddr), 16);
                __builtin_memcpy(&(key.field2), &(hdr->ipv6.dstAddr), 16);
                key.field3 = hdr->ipv6.nextHdr;
                key.field4 = bpf_htons(meta->srcPort);
                key.field5 = bpf_htons(meta->dstPort);
                struct p4tc_table_entry_act_bpf *act_bpf;
                /* value */
                struct Main_ct_flow_table_value *value = NULL;
                /* perform lookup */
                act_bpf = bpf_p4tc_tbl_read(skb, &params, sizeof(params), &key, sizeof(key));
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
                        case MAIN_CT_FLOW_TABLE_ACT__NOACTION: 
                            {
                            }
                            break;
                        case MAIN_CT_FLOW_TABLE_ACT_MAIN_CT_FLOW_MISS: 
                            {
/* add_entry(""NoAction"", {}, 0) */
                                struct p4tc_table_entry_act_bpf update_act_bpf = {};
                                update_act_bpf.act_id = 0;

                                /* construct key */
                                struct p4tc_table_entry_create_bpf_params__local update_params = {
                                    .act_bpf = update_act_bpf,
                                    .pipeid = p4tc_filter_fields.pipeid,
                                    .handle = p4tc_filter_fields.handle,
                                    .classid = p4tc_filter_fields.classid,
                                    .chain = p4tc_filter_fields.chain,
                                    .proto = p4tc_filter_fields.proto,
                                    .prio = p4tc_filter_fields.prio,
                                    .tblid = 1,
                                    .profile_id = 0
                                };
                                bpf_p4tc_entry_create_on_miss(skb, &update_params, sizeof(update_params), &key, sizeof(key));
                            }
                            break;
                    }
                } else {
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
        int outHeaderLength = 0;
        if (hdr->eth.ebpf_valid) {
            outHeaderLength += 112;
        }
;        if (hdr->ipv6.ebpf_valid) {
            outHeaderLength += 320;
        }
;        if (hdr->tcp.ebpf_valid) {
            outHeaderLength += 32;
        }
;        if (hdr->udp.ebpf_valid) {
            outHeaderLength += 32;
        }
;
        __u16 saved_proto = 0;
        bool have_saved_proto = false;
        // bpf_skb_adjust_room works only when protocol is IPv4 or IPv6
        // 0x0800 = IPv4, 0x86dd = IPv6
        if ((skb->protocol != bpf_htons(0x0800)) && (skb->protocol != bpf_htons(0x86dd))) {
            saved_proto = skb->protocol;
            have_saved_proto = true;
            bpf_p4tc_skb_set_protocol(skb, &sa->set, bpf_htons(0x0800));
            bpf_p4tc_skb_meta_set(skb, &sa->set, sizeof(sa->set));
        }
        ;

        int outHeaderOffset = BYTES(outHeaderLength) - (hdr_start - (u8*)pkt);
        if (outHeaderOffset != 0) {
            int returnCode = 0;
            returnCode = bpf_skb_adjust_room(skb, outHeaderOffset, 1, 0);
            if (returnCode) {
                return TC_ACT_SHOT;
            }
        }

        if (have_saved_proto) {
            bpf_p4tc_skb_set_protocol(skb, &sa->set, saved_proto);
            bpf_p4tc_skb_meta_set(skb, &sa->set, sizeof(sa->set));
        }

        pkt = ((void*)(long)skb->data);
        ebpf_packetEnd = ((void*)(long)skb->data_end);
        ebpf_packetOffsetInBits = 0;
        if (hdr->eth.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 112)) {
                return TC_ACT_SHOT;
            }
            
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
;        if (hdr->ipv6.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 320)) {
                return TC_ACT_SHOT;
            }
            
            ebpf_byte = ((char*)(&hdr->ipv6.version))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 4, 4, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 4;

            ebpf_byte = ((char*)(&hdr->ipv6.traffiClass))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 4, 0, (ebpf_byte >> 4));
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0 + 1, 4, 4, (ebpf_byte));
            ebpf_packetOffsetInBits += 8;

            storePrimitive32((u8 *)&hdr->ipv6.flowLabel, 20, (htonl(getPrimitive32(hdr->ipv6.flowLabel, 20) << 12)));
            ebpf_byte = ((char*)(&hdr->ipv6.flowLabel))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 4, 0, (ebpf_byte >> 4));
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0 + 1, 4, 4, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.flowLabel))[1];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 1, 4, 0, (ebpf_byte >> 4));
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 1 + 1, 4, 4, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.flowLabel))[2];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 2, 4, 0, (ebpf_byte >> 4));
            ebpf_packetOffsetInBits += 20;

            hdr->ipv6.payloadLen = bpf_htons(hdr->ipv6.payloadLen);
            ebpf_byte = ((char*)(&hdr->ipv6.payloadLen))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.payloadLen))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            ebpf_byte = ((char*)(&hdr->ipv6.nextHdr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_packetOffsetInBits += 8;

            ebpf_byte = ((char*)(&hdr->ipv6.hopLimit))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_packetOffsetInBits += 8;

            ebpf_byte = ((char*)(&hdr->ipv6.srcAddr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.srcAddr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.srcAddr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.srcAddr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.srcAddr))[4];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 4, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.srcAddr))[5];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 5, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.srcAddr))[6];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 6, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.srcAddr))[7];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 7, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.srcAddr))[8];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 8, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.srcAddr))[9];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 9, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.srcAddr))[10];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 10, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.srcAddr))[11];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 11, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.srcAddr))[12];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 12, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.srcAddr))[13];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 13, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.srcAddr))[14];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 14, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.srcAddr))[15];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 15, (ebpf_byte));
            ebpf_packetOffsetInBits += 128;

            ebpf_byte = ((char*)(&hdr->ipv6.dstAddr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.dstAddr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.dstAddr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.dstAddr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.dstAddr))[4];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 4, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.dstAddr))[5];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 5, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.dstAddr))[6];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 6, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.dstAddr))[7];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 7, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.dstAddr))[8];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 8, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.dstAddr))[9];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 9, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.dstAddr))[10];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 10, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.dstAddr))[11];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 11, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.dstAddr))[12];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 12, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.dstAddr))[13];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 13, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.dstAddr))[14];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 14, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv6.dstAddr))[15];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 15, (ebpf_byte));
            ebpf_packetOffsetInBits += 128;

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
;        if (hdr->udp.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 32)) {
                return TC_ACT_SHOT;
            }
            
            hdr->udp.srcPort = bpf_htons(hdr->udp.srcPort);
            ebpf_byte = ((char*)(&hdr->udp.srcPort))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->udp.srcPort))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            hdr->udp.dstPort = bpf_htons(hdr->udp.dstPort);
            ebpf_byte = ((char*)(&hdr->udp.dstPort))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->udp.dstPort))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

        }
;
    }
    return -1;
}
SEC("p4tc/main")
int tc_ingress_func(struct __sk_buff *skb) {
    struct skb_aggregate skbstuff;
    struct pna_global_metadata *compiler_meta__ = (struct pna_global_metadata *) skb->cb;
    compiler_meta__->drop = false;
    compiler_meta__->recirculate = false;
    compiler_meta__->egress_port = 0;
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
    ret = process(skb, (struct headers_t *) hdr, compiler_meta__, &skbstuff);
    if (ret != -1) {
        return ret;
    }
    if (!compiler_meta__->drop && compiler_meta__->recirculate) {
        compiler_meta__->recirculated = true;
        return TC_ACT_UNSPEC;
    }
    if (!compiler_meta__->drop && compiler_meta__->egress_port == 0)
        return TC_ACT_OK;
    return bpf_redirect(compiler_meta__->egress_port, 0);
}
char _license[] SEC("license") = "GPL";
