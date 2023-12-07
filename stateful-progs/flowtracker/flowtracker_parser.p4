#include <core.p4>
#include <tc/pna.p4>

#define IP_PROTO_TCP 0x6
#define IP_PROTO_UDP 0x11

typedef bit<48>  EthernetAddress;
typedef bit<32>  IPv4Address;

header ethernet_t {
    @tc_type("macaddr") EthernetAddress dstAddr;
    @tc_type("macaddr") EthernetAddress srcAddr;
    bit<16>         etherType;
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
    @tc_type("ipv4") IPv4Address srcAddr;
    @tc_type("ipv4") IPv4Address dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
}

// User-defined struct containing all of those headers parsed in the
// main parser.
struct headers_t {
    ethernet_t eth;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
}

parser MainParserImpl(
    packet_in pkt,
    out   headers_t hdr,
    inout my_ingress_metadata_t meta,
    in    pna_main_parser_input_metadata_t istd)
{
    state start {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etherType) {
            0x0800  : parse_ipv4;
            default : reject;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP : parse_tcp;
            IP_PROTO_UDP : parse_udp;
            default : reject;
        }
    }
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
}
