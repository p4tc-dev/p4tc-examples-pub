/* -*- P4_16 -*- */

/*
 * Standard ethernet header
 */
header ethernet_t {
    @tc_type("macaddr") bit<48> dstAddr;
    @tc_type("macaddr") bit<48> srcAddr;
    bit<16> etherType;
}

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
}

header arp_ipv4_t {
    @tc_type("macaddr") bit<48> sha;
    @tc_type("ipv4") bit<32> spa;
    @tc_type("macaddr") bit<48> tha;
    @tc_type("ipv4") bit<32> tpa;
}

struct my_ingress_headers_t {
    ethernet_t   ethernet;
    arp_t        arp;
    arp_ipv4_t   arp_ipv4;
}

const bit<16> ETHERTYPE_ARP = 0x0806;
const bit<16> ARP_HTYPE = 0x0001;
const bit<16> ARP_PTYPE = 0x0800;
const bit<8>  ARP_HLEN  = 6;
const bit<8>  ARP_PLEN  = 4;
const bit<16> ARP_REQ = 1;
const bit<16> ARP_REPLY = 2;



/***********************  P A R S E R  **************************/
parser Ingress_Parser(
        packet_in pkt,
        out   my_ingress_headers_t  hdr,
        inout my_ingress_metadata_t meta,
        in    pna_main_parser_input_metadata_t istd)
{
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
	    ETHERTYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_arp {
	pkt.extract(hdr.arp);
	pkt.extract(hdr.arp_ipv4);
	transition select(hdr.arp.oper) {
	    ARP_REQ: accept;
            default: reject;
	}
    }
}
