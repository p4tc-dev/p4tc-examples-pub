/* -*- P4_16 -*- */

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    @tc_type("dev") PortId_t ingress_port;
    bool send_digest;
}