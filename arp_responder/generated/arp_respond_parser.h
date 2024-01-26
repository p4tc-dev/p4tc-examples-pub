/* Automatically generated by p4c-pna-p4tc from arp_respond.p4 on Fri Dec  1 22:15:24 2023
 */
#include "ebpf_kernel.h"

#include <stdbool.h>
#include <linux/if_ether.h>
#include "pna.h"

#define EBPF_MASK(t, w) ((((t)(1)) << (w)) - (t)1)
#define BYTES(w) ((w) / 8)
#define write_partial(a, w, s, v) do { *((u8*)a) = ((*((u8*)a)) & ~(EBPF_MASK(u8, w) << s)) | (v << s) ; } while (0)
#define write_byte(base, offset, v) do { *(u8*)((base) + (offset)) = (v); } while (0)
#define bpf_trace_message(fmt, ...)


struct my_ingress_metadata_t {
};
struct empty_metadata_t {
};
struct ethernet_t {
    u64 dstAddr; /* bit<48> */
    u64 srcAddr; /* bit<48> */
    u16 etherType; /* bit<16> */
    u8 ebpf_valid;
};
struct arp_t {
    u16 htype; /* bit<16> */
    u16 ptype; /* bit<16> */
    u8 hlen; /* bit<8> */
    u8 plen; /* bit<8> */
    u16 oper; /* bit<16> */
    u8 ebpf_valid;
};
struct arp_ipv4_t {
    u64 sha; /* bit<48> */
    u32 spa; /* bit<32> */
    u64 tha; /* bit<48> */
    u32 tpa; /* bit<32> */
    u8 ebpf_valid;
};
struct my_ingress_headers_t {
    struct ethernet_t ethernet; /* ethernet_t */
    struct arp_t arp; /* arp_t */
    struct arp_ipv4_t arp_ipv4; /* arp_ipv4_t */
};

struct hdr_md {
    struct my_ingress_headers_t cpumap_hdr;
    struct my_ingress_metadata_t cpumap_usermeta;
    unsigned ebpf_packetOffsetInBits;
    __u8 __hook;
};

