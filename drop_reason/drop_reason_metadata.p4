/* -*- P4_16 -*- */

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

enum bit<8> DROP_REASON {
    PARSER_REJECTED = 1,
    TABLE_MISS = 2
};

struct my_ingress_metadata_t {
    @tc_type("dev") PortId_t ingress_port;
    DROP_REASON drop_reason;
    bool send_digest;
}
