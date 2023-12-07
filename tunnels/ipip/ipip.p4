#include "ipip_parser.p4"

void ip_ttl_dec(InternetChecksum chk, inout ipv4_t ip)
{
      chk.clear();

      chk.set_state(~ip.hdrChecksum);

      chk.subtract({ ip.ttl, ip.protocol });

      ip.ttl = ip.ttl - 1;
      chk.add({ ip.ttl, ip.protocol });

      ip.hdrChecksum = chk.get();
}

void ip_checksum(InternetChecksum chk, inout ipv4_t ip)
{
   chk.clear();
   chk.add({
      /* 16-bit word 0 */ ip.version, ip.ihl, ip.diffserv,
      /* 16-bit word 1 */ ip.totalLen,
      /* 16-bit word 2 */ ip.identification,
      /* 16-bit word 3 */ ip.flags, ip.fragOffset,
      /* 16-bit word 4 */ ip.ttl, ip.protocol,
      /* 16-bit word 5 skip ip.hdrChecksum, */
      /* 16-bit words 6-7 */ ip.srcAddr,
      /* 16-bit words 8-9 */ ip.dstAddr
   });
   ip.hdrChecksum = chk.get();
}

void ipip_push(inout headers_t hdr, in metadata_t meta)
{
   hdr.inner = hdr.outer;
   hdr.outer.srcAddr = meta.src;
   hdr.outer.dstAddr = meta.dst;
   hdr.outer.ttl = 64;
   hdr.outer.protocol = 4; /* IPIP */
   /* Assume MTU can accomodate +20 bytes */
   hdr.outer.totalLen = hdr.outer.totalLen + 20;
   hdr.outer.hdrChecksum = 0;
}

/***************** M A T C H - A C T I O N  *********************/
control Main(
    inout headers_t  hdr,
    inout metadata_t meta,
    in pna_main_input_metadata_t  istd,
    inout pna_main_output_metadata_t ostd
)
{
   action set_ipip(@tc_type("ipv4") bit<32> src, @tc_type("ipv4") bit<32> dst, @tc_type("dev") PortId_t port) {
      meta.src = src;
      meta.dst = dst;
      meta.push = true;
      send_to_port(port);
   }

   action set_nh(@tc_type("macaddr") bit<48> dmac, @tc_type("dev") PortId_t port) {
      hdr.ethernet.dstAddr = dmac;
      send_to_port(port);
   }

   action drop() {
      drop_packet();
   }

   table fwd_table {
      key = {
         istd.input_port : exact @tc_type("dev") @name("port");
      }
      actions = {
         set_ipip;
         set_nh;
         drop;
      }
      default_action = drop;
   }

   apply {
      if (hdr.outer.isValid()) { /* applies to both ipip and plain ip */
         fwd_table.apply(); /* lookup based on incoming netdev */
         if (hdr.inner.isValid()) { /* incoming packet ipip */
            /* Pop the ipip header by invalidating outer header */
            hdr.outer.setInvalid();
         }
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
	if (meta.push && hdr.outer.isValid()) {
               /* Push the ipip header */
               ipip_push(hdr, meta);
               ip_checksum(chk, hdr.outer);
               ip_ttl_dec(chk, hdr.inner);
	}
        pkt.emit(hdr.outer);
        pkt.emit(hdr.inner);
    }
}

/************ F I N A L   P A C K A G E ******************************/
PNA_NIC(
    Parser(),
    Main(),
    Deparser()
) main;
