/* -*- P4_16 -*- */

#include <core.p4>
#include <tc/pna.p4>
#include "drop_reason_metadata.p4"
#include "drop_reason_parser.p4"

#define L3_TABLE_SIZE 2048

struct mac_learn_digest_t {
    @tc_type("macaddr") bit<48> srcAddr;
    @tc_type("dev") PortId_t ingress_port;
    DROP_REASON drop_reason;
};

/***************** M A T C H - A C T I O N  *********************/

control ingress(
    inout my_ingress_headers_t  hdr,
    inout my_ingress_metadata_t meta,
    in    pna_main_input_metadata_t  istd,
    inout pna_main_output_metadata_t ostd
)
{
   action send_nh(@tc_type("dev") PortId_t port, @tc_type("macaddr") bit<48> srcMac, @tc_type("macaddr") bit<48> dstMac) {
        hdr.ethernet.srcAddr = srcMac;
        hdr.ethernet.dstAddr = dstMac;
        send_to_port(port);
   }

   action drop() {
        meta.ingress_port = istd.input_port;
        meta.drop_reason = DROP_REASON.TABLE_MISS;
        meta.send_digest = true;
        drop_packet();
   }

    table nh_table {
        key = {
            hdr.ipv4.dstAddr : exact @tc_type("ipv4") @name("dstAddr");
        }
        actions = {
            send_nh;
            drop;
        }
        size = L3_TABLE_SIZE;
        const default_action = drop;
    }

    apply {
        if (!meta.send_digest && hdr.ipv4.isValid()) {
            nh_table.apply();
        }
    }
}

    /*********************  D E P A R S E R  ************************/

control Ingress_Deparser(
    packet_out pkt,
    inout    my_ingress_headers_t hdr,
    in    my_ingress_metadata_t meta,
    in    pna_main_output_metadata_t ostd)
{
   Digest<mac_learn_digest_t>() digest_inst;

   apply {
       pkt.emit(hdr.ethernet);
       pkt.emit(hdr.ipv4);
       if (meta.send_digest) {
           mac_learn_digest_t mac_learn_digest;
           mac_learn_digest.srcAddr = hdr.ethernet.srcAddr;
           mac_learn_digest.ingress_port = meta.ingress_port;
           mac_learn_digest.drop_reason = meta.drop_reason;
           digest_inst.pack(mac_learn_digest);
       }
   }
}

/************ F I N A L   P A C K A G E ******************************/

PNA_NIC(
    Ingress_Parser(),
    ingress(),
    Ingress_Deparser()
) main;
