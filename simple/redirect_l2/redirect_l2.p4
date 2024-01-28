/* -*- P4_16 -*- */

#include <core.p4>
#include <tc/pna.p4>
#include "redirect_l2_metadata.p4"
#include "redirect_l2_parser.p4"
#define REDIR_TABLE_SIZE 262144

/***************** M A T C H - A C T I O N  *********************/

control ingress(
    inout my_ingress_headers_t  hdr,
    inout my_ingress_metadata_t meta,
    in    pna_main_input_metadata_t  istd,
    inout pna_main_output_metadata_t ostd
)
{
   action send_nh() {
        ...
   }

    table nh_table {
        key = {
            hdr.ipv4.srcAddr : exact @tc_type("ipv4") @name("srcAddr");
        }
        actions = {
            send_nh;
        }
        size = REDIR_TABLE_SIZE;
    }

    apply {
        nh_table.apply();
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
