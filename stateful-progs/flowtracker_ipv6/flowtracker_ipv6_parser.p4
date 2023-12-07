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

header ipv6_t {
    bit<4> version;
    bit<8> traffiClass;
    bit<20> flowLabel;
    bit<16> payloadLen;
    bit<8> nextHdr;
    bit<8> hopLimit;
    @tc_type("ipv6") bit<128> srcAddr;
    @tc_type("ipv6") bit<128> dstAddr;
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
    ipv6_t     ipv6;
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
            0x86DD  : parse_ipv6;
            default : reject;
        }
    }
    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr) {
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
