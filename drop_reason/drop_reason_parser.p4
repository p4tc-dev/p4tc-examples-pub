/* -*- P4_16 -*- */

/*
 * CONST VALUES FOR TYPES
 */
const bit<8> IP_PROTO_TCP = 0x06;
const bit<16> ETHERTYPE_IPV4 = 0x0800;

/*
 * Standard ethernet header
 */
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

struct my_ingress_headers_t {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
}

    /***********************  P A R S E R  **************************/
parser Ingress_Parser(
        packet_in pkt,
        out   my_ingress_headers_t  hdr,
        inout my_ingress_metadata_t meta,
        in    pna_main_parser_input_metadata_t istd)
{

    state start {
        meta.send_digest = false;
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        /* Have to unconditionally transition because the compiler doesn't allow transitions in if-stataments*/
        transition parse_ipv4;
    }
    state parse_ipv4 {
        if (hdr.ethernet.etherType == ETHERTYPE_IPV4) {
            pkt.extract(hdr.ipv4);
        }

        if (!hdr.ipv4.isValid() || hdr.ipv4.protocol != IP_PROTO_TCP) {
            meta.send_digest = true;
            meta.ingress_port = istd.input_port;
            meta.drop_reason = DROP_REASON.PARSER_REJECTED;
        }
        transition accept;
    }
}
