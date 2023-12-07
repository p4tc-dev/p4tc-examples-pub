#include "routing_parser.p4"

void ip_ttl_dec(InternetChecksum chk, inout ipv4_t ip) {

   /* Decrement ttl
    * HC' = (~HC) + ~m + m'
    */

   chk.clear();
   chk.set_state(~ip.hdrChecksum);

   chk.subtract({ ip.ttl, ip.protocol });
   ip.ttl = ip.ttl - 1;
   chk.add({ ip.ttl, ip.protocol });

   ip.hdrChecksum = chk.get();
}

/***************** M A T C H - A C T I O N  *********************/

control Main(
    inout headers_t  hdr,
    inout metadata_t meta,
    in    pna_main_input_metadata_t  istd,
    inout pna_main_output_metadata_t ostd
)
{
   bit<32> nh_index;

   action drop() {
      drop_packet();
   }

   action set_nh(@tc_type("macaddr") bit<48> dmac, @tc_type("dev") PortId_t port) {
      hdr.ethernet.dstAddr = dmac;
      send_to_port(port);
   }

   table nh_table {
      key = {
         nh_index : exact;
      }
      actions = {
         drop;
         set_nh;
      }
      default_action = drop;
   }

   action set_nhid(bit<32> index) {
      nh_index = index;
   }

   table fib_table {
      key = {
         hdr.ip.dstAddr : lpm @tc_type("ipv4") @name("prefix");
      }
      actions = {
         set_nhid;
      }
      /* 0 is the default route */
      default_action = set_nhid(0);
   }

   apply {
      if (hdr.ip.isValid() && hdr.ip.ttl > 1) {
            fib_table.apply();
            nh_table.apply();
      } else {
           drop_packet();
      }
   }
}

/*********************  D E P A R S E R  ************************/
control Deparser(
    packet_out pkt,
    inout    headers_t hdr,
    in    metadata_t meta,
    in    pna_main_output_metadata_t ostd)
{
   InternetChecksum() chk;

    apply {
        pkt.emit(hdr.ethernet);
        ip_ttl_dec(chk, hdr.ip);
        pkt.emit(hdr.ip);
    }
}

/************ F I N A L   P A C K A G E ******************************/
PNA_NIC(
    Parser(),
    Main(),
    Deparser()
) main;
