/************MONITOR*************/

typedef bit<32> flowIDHash_t;
const bit<32> FILTER_TABLE_SIZE = 32w1024;
const bit<32> METRICS_TABLE_SIZE = 32w32;

/*************************/

/************MONITOR*************/

struct flow_t {
    bit<8>  protocol;
    bit<32> srcAddr;
    bit<32> dstAddr;
    bit<16> srcPort;
    bit<16> dstPort;
}

struct metrics_t {
    //flow_t  flow;
    bit<8>  protocol;
    bit<32> srcAddr;
    bit<32> dstAddr;
    bit<16> srcPort;
    bit<16> dstPort;
    bit<8>  ctr_flows;
    bit<32>  ctr_packets;
    //bit<48>  last_seen;
}

struct flow_idx_t {
    flowIDHash_t filter_idx1;
    flowIDHash_t filter_idx2;
    flowIDHash_t filter_idx3;
    flowIDHash_t metrics_idx1;
    flowIDHash_t metrics_idx2;
    flowIDHash_t metrics_idx3;
    bit<1>  is_stored;
}
/*************************/