/* -*- P4_16 -*- */

#include <core.p4>
#include <tc/pna.p4>
#include "arp_respond_metadata.p4"
#include "arp_respond_parser.p4"
#define ARP_TABLE_SIZE 1024

/***************** M A T C H - A C T I O N  *********************/

control ingress(
    inout my_ingress_headers_t  hdr,
    inout my_ingress_metadata_t meta,
    in    pna_main_input_metadata_t  istd,
    inout pna_main_output_metadata_t ostd
)
{
   action arp_reply(@tc_type("macaddr") bit<48> rmac) {
	hdr.arp.oper = ARP_REPLY;
	hdr.arp_ipv4.tha = hdr.arp_ipv4.sha;
	hdr.arp_ipv4.sha = rmac;
	hdr.arp_ipv4.spa = hdr.arp_ipv4.tpa;
	hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
	hdr.ethernet.srcAddr = rmac;
        send_to_port(istd.input_port);
   }

   action drop() {
        drop_packet();
   }

    table arp_table {
        key = {
            hdr.arp_ipv4.tpa : exact @tc_type("ipv4") @name("IPaddr");
        }
        actions = {
            arp_reply;
            drop;
        }
        size = ARP_TABLE_SIZE;
        const default_action = drop;
    }

    apply {
        arp_table.apply();
    }
}

    /*********************  D E P A R S E R  ************************/

control Ingress_Deparser(
    packet_out pkt,
    in    my_ingress_headers_t hdr,
    in    my_ingress_metadata_t meta,
    in    pna_main_output_metadata_t ostd)
{
    apply {
        pkt.emit(hdr.ethernet);
	pkt.emit(hdr.arp);
	pkt.emit(hdr.arp_ipv4);
    }
}

/************ F I N A L   P A C K A G E ******************************/

PNA_NIC(
    Ingress_Parser(),
    ingress(),
    Ingress_Deparser()
) main;
