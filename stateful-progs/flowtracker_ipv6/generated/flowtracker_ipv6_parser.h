/* Automatically generated by p4c-pna-p4tc from /home/vnogueira/kvmshare/p4tc-examples/stateful-progs/flowtracker_ipv6/flowtracker_ipv6.p4 on Tue Dec  5 21:32:41 2023
 */
#include "ebpf_kernel.h"


#define EBPF_MASK(t, w) ((((t)(1)) << (w)) - (t)1)
#define BYTES(w) ((w) / 8)
#define write_partial(a, w, s, v) do { *((u8*)a) = ((*((u8*)a)) & ~(EBPF_MASK(u8, w) << s)) | (v << s) ; } while (0)
#define write_byte(base, offset, v) do { *(u8*)((base) + (offset)) = (v); } while (0)
#define bpf_trace_message(fmt, ...)


struct my_ingress_metadata_t {
    u16 srcPort; /* bit<16> */
    u16 dstPort; /* bit<16> */
};
struct ethernet_t {
    u64 dstAddr; /* EthernetAddress */
    u64 srcAddr; /* EthernetAddress */
    u16 etherType; /* bit<16> */
    u8 ebpf_valid;
};
struct ipv6_t {
    u8 version; /* bit<4> */
    u8 traffiClass; /* bit<8> */
    u32 flowLabel; /* bit<20> */
    u16 payloadLen; /* bit<16> */
    u8 nextHdr; /* bit<8> */
    u8 hopLimit; /* bit<8> */
    u8 srcAddr[16]; /* bit<128> */
    u8 dstAddr[16]; /* bit<128> */
    u8 ebpf_valid;
};
struct udp_t {
    u16 srcPort; /* bit<16> */
    u16 dstPort; /* bit<16> */
    u8 ebpf_valid;
};
struct tcp_t {
    u16 srcPort; /* bit<16> */
    u16 dstPort; /* bit<16> */
    u8 ebpf_valid;
};
struct headers_t {
    struct ethernet_t eth; /* ethernet_t */
    struct ipv6_t ipv6; /* ipv6_t */
    struct tcp_t tcp; /* tcp_t */
    struct udp_t udp; /* udp_t */
};
struct hdr_md {
    struct headers_t cpumap_hdr;
    struct my_ingress_metadata_t cpumap_usermeta;
    unsigned ebpf_packetOffsetInBits;
    __u8 __hook;
};

