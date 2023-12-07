/* -*- P4_16 -*- */

#include <core.p4>
#include <tc/pna.p4>
#include "simple_l3_metadata.p4"
#include "simple_l3_parser.p4"

#define L3_TABLE_SIZE 2048

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
	/*XXX: Why are we checking for TCP? Parser will reject if it is not TCP*/
        if (hdr.ipv4.isValid() && hdr.ipv4.protocol == IP_PROTO_TCP) {
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
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
    }
}

/************ F I N A L   P A C K A G E ******************************/

PNA_NIC(
    Ingress_Parser(),
    ingress(),
    Ingress_Deparser()
) main;
