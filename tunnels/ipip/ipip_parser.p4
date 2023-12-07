#include <core.p4>
#include <tc/pna.p4>

struct metadata_t {
    @tc_type("ipv4") bit<32> src;
    @tc_type("ipv4") bit<32> dst;
    bool    push;
}

header ethernet_t {
    @tc_type("macaddr") bit<48> dstAddr;
    @tc_type("macaddr") bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    @tc_type("ipv4") bit<32> srcAddr;
    @tc_type("ipv4") bit<32> dstAddr;
}

struct headers_t {
    ethernet_t   ethernet;
    ipv4_t       outer;
    ipv4_t       inner;
}

#define ETHERTYPE_IPV4 0x0800
#define IPPROTO_IPV4 0x4

/***********************  P A R S E R  **************************/
parser Parser(
        packet_in pkt,
        out   headers_t  hdr,
        inout metadata_t meta,
        in    pna_main_parser_input_metadata_t istd)
{
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.outer);
        transition select(hdr.outer.protocol) {
            IPPROTO_IPV4: parse_ipv4_inner;
            default: accept;
        }
    }

    state parse_ipv4_inner {
        pkt.extract(hdr.inner);
        transition accept;
    }
}
