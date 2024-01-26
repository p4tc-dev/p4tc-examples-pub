#include <core.p4>
#include <tc/pna.p4>
#include "flowtracker_metadata.p4"
#include "flowtracker_parser.p4"

typedef bit<80> PacketByteCounter_t;

control Main(
    inout headers_t hdr,                 // from main parser
    inout my_ingress_metadata_t meta,               // from main parser, to "next block"
    in    pna_main_input_metadata_t istd,
    inout pna_main_output_metadata_t ostd)
{
    DirectCounter<PacketByteCounter_t>(PNA_CounterType_t.PACKETS_AND_BYTES) global_counter;

    action ct_flow_miss() {
       add_entry(action_name = "NoAction",  // name of action
                 action_params = {}, 
                 expire_time_profile_id = (ExpireTimeProfileId_t)0);
    }

    table ct_flow_table {
        key = {
            istd.input_port : exact @tc_type("dev") @name("input_port");
            hdr.ipv4.srcAddr : exact @tc_type("ipv4") @name("srcAddr");
            hdr.ipv4.dstAddr : exact @tc_type("ipv4") @name("dstAddr");
            hdr.ipv4.protocol : exact;
            meta.srcPort : exact @tc_type("be16") @name("srcPort");
            meta.dstPort : exact @tc_type("be16") @name("dstPort");
        }
        actions = {
            NoAction;
            @defaultonly ct_flow_miss;
        }
        default_action = ct_flow_miss;
        pna_idle_timeout = PNA_IdleTimeout_t.NOTIFY_CONTROL;
        pna_direct_counter = global_counter;
    }

    apply {
        if (hdr.tcp.isValid()) {
            meta.srcPort = hdr.tcp.srcPort;
            meta.dstPort = hdr.tcp.dstPort;
        } else if (hdr.udp.isValid()) {
            meta.srcPort = hdr.udp.srcPort;
            meta.dstPort = hdr.udp.dstPort;
        }

        ct_flow_table.apply();
    }
}

control MainDeparserImpl(
    packet_out pkt,
    inout headers_t hdr,
    in my_ingress_metadata_t meta,
    in pna_main_output_metadata_t ostd)
{
    apply {
        pkt.emit(hdr.eth);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
    }
}

// BEGIN:Package_Instantiation_Example
PNA_NIC(
    MainParserImpl(),
    Main(),
    MainDeparserImpl()
    ) main;
// END:Package_Instantiation_Example
