/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

#include "includes/headers/ethernet_hdr.p4"
#include "includes/headers/ipv4_hdr.p4"
#include "includes/headers/icmp_hdr.p4"
#include "includes/headers/udp_hdr.p4"
#include "includes/headers/tcp_hdr.p4"

/*************************************************************************
*********************** CONSTANTS AND NEW TYPES  **************************
*************************************************************************/

#include "includes/types.p4"

/************MONITOR*************/

typedef bit<32> flowIDHash_t;
typedef bit<104> flowID_t;
const bit<32> FILTER_TABLE_SIZE = 32w1024;
const bit<32> METRICS_TABLE_SIZE = 32w32;

/*************************/

const bit<16> TYPE_IPV4 = 0x800;
const bit<4> NORMAL_STATE = 1;
const bit<4> MALICIOUS_STATE = 2;

/*************************************************************************
***************************** STRUCTURES  ********************************
*************************************************************************/

struct state_metadata_t {
    bit<4> state;
}


/************MONITOR*************/

/*struct flow_t {
    bit<8>  protocol;
    bit<32> srcAddr;
    bit<32> dstAddr;
    bit<16> srcPort;
    bit<16> dstPort;
}*/

struct flow_t {
    flowID_t  flow_id;
    bit<8>  ctr_flows;
    bit<32>  ctr_packets;
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

struct metadata {
    state_metadata_t state_m;
    flow_idx_t flow_idx_m;
    flow_t   flow_m;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    icmp_t       icmp;
    udp_t        udp;
    tcp_t        tcp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w0x1: parse_icmp;
            8w0x6: parse_tcp;
            8w0x11: parse_udp;
            default: accept;
        }
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    /* Features */
    //register<bit<48>>(16384) last_seen;
    //register<bit<48>>(16384) time_gap;
    //counter(CounterType.packets_and_bytes) flow_stats;

    /************MONITOR*************/
    register<bit<1>>(FILTER_TABLE_SIZE) flow_filter;
    register<bit<8>>(METRICS_TABLE_SIZE) ctr_flows;
    register<flowIDHash_t>(METRICS_TABLE_SIZE) flow_xor_idx1;
    register<flowIDHash_t>(METRICS_TABLE_SIZE) flow_xor_idx2;
    register<flowIDHash_t>(METRICS_TABLE_SIZE) flow_xor_idx3;
    //register<bit<32>>(METRICS_TABLE_SIZE) flow_xor_id;
    register<bit<8>>(METRICS_TABLE_SIZE) flow_xor_proto;
    register<bit<32>>(METRICS_TABLE_SIZE) flow_xor_srcAddr;
    register<bit<32>>(METRICS_TABLE_SIZE) flow_xor_dstAddr;
    register<bit<16>>(METRICS_TABLE_SIZE) flow_xor_srcPort;
    register<bit<16>>(METRICS_TABLE_SIZE) flow_xor_dstPort;
    //register<bit<32>>(METRICS_TABLE_SIZE) ctr_packets;


    //register<bit<48>>(METRICS_TABLE_SIZE) last_seen;
    counter(METRICS_TABLE_SIZE, CounterType.packets_and_bytes) ctr_packets;
    //counter(TABLE_SIZE, CounterType.bytes) counting_bytes;
    /*************************/


    /* Marked packets */
    counter(32w1024, CounterType.packets_and_bytes) ctr_normal;
    counter(32w1024, CounterType.packets_and_bytes) ctr_suspicious;

    action drop() {
        mark_to_drop();
    }

    action mark_as_normal() {
        meta.state_m.state = NORMAL_STATE;
    }

    action mark_as_suspicious() {
        meta.state_m.state = MALICIOUS_STATE;
    }

    /************MONITOR*************/
    action calculate_flow_idx() {
        hash(meta.flow_idx_m.filter_idx1, HashAlgorithm.crc32,
                    32w0,
                    {meta.flow_m.flow_id},
                    FILTER_TABLE_SIZE);
        hash(meta.flow_idx_m.filter_idx2, HashAlgorithm.crc16,
                    32w0,
                    {meta.flow_m.flow_id},
                    FILTER_TABLE_SIZE);
        hash(meta.flow_idx_m.filter_idx3, HashAlgorithm.csum16,
                    32w0,
                    {meta.flow_m.flow_id},
                    FILTER_TABLE_SIZE);
        hash(meta.flow_idx_m.metrics_idx1, HashAlgorithm.crc32,
                    32w0,
                    {meta.flow_m.flow_id},
                    METRICS_TABLE_SIZE);
        hash(meta.flow_idx_m.metrics_idx2, HashAlgorithm.crc16,
                    32w0,
                    {meta.flow_m.flow_id},
                    METRICS_TABLE_SIZE);
        hash(meta.flow_idx_m.metrics_idx3, HashAlgorithm.csum16,
                    32w0,
                    {meta.flow_m.flow_id},
                    METRICS_TABLE_SIZE);
    }

    action check_flow_track(bit<16> srcPort, bit<16> dstPort) {

        meta.flow_m.flow_id = hdr.ipv4.srcAddr ++ hdr.ipv4.dstAddr ++ srcPort ++ dstPort ++ hdr.ipv4.protocol;

        calculate_flow_idx();

        bit<1> query_idx1 = 0;
        bit<1> query_idx2 = 0;
        bit<1> query_idx3 = 0;

        flow_filter.read(query_idx1, meta.flow_idx_m.filter_idx1);
        flow_filter.read(query_idx2, meta.flow_idx_m.filter_idx2);
        flow_filter.read(query_idx3, meta.flow_idx_m.filter_idx3);

        meta.flow_idx_m.is_stored = query_idx1 & query_idx2 & query_idx3;
    }

    action create_flow_track() {
        flow_filter.write(meta.flow_idx_m.filter_idx1, 0b1);
        flow_filter.write(meta.flow_idx_m.filter_idx2, 0b1);
        flow_filter.write(meta.flow_idx_m.filter_idx3, 0b1);

        /* Update ctr_flow */
        ctr_flows.read(meta.flow_m.ctr_flows,meta.flow_idx_m.metrics_idx1);
        ctr_flows.write(meta.flow_idx_m.metrics_idx1,meta.flow_m.ctr_flows+1);
        ctr_flows.read(meta.flow_m.ctr_flows,meta.flow_idx_m.metrics_idx2);
        ctr_flows.write(meta.flow_idx_m.metrics_idx2,meta.flow_m.ctr_flows+1);
        ctr_flows.read(meta.flow_m.ctr_flows,meta.flow_idx_m.metrics_idx3);
        ctr_flows.write(meta.flow_idx_m.metrics_idx3,meta.flow_m.ctr_flows+1);

        flowIDHash_t query_idx1 = 0;
        flowIDHash_t query_idx2 = 0;
        flowIDHash_t query_idx3 = 0;

        /* Update flow_xor_idx1 */
        flow_xor_idx1.read(query_idx1,meta.flow_idx_m.metrics_idx1);
        query_idx1 = query_idx1 ^ meta.flow_idx_m.metrics_idx1;
        flow_xor_idx1.write(meta.flow_idx_m.metrics_idx1,query_idx1);
        flow_xor_idx1.read(query_idx1,meta.flow_idx_m.metrics_idx2);
        query_idx1 = query_idx1 ^ meta.flow_idx_m.metrics_idx1;
        flow_xor_idx1.write(meta.flow_idx_m.metrics_idx2,query_idx1);
        flow_xor_idx1.read(query_idx1,meta.flow_idx_m.metrics_idx3);
        query_idx1 = query_idx1 ^ meta.flow_idx_m.metrics_idx1;
        flow_xor_idx1.write(meta.flow_idx_m.metrics_idx3,query_idx1);

        /* Update flow_xor_idx2 */
        flow_xor_idx2.read(query_idx2,meta.flow_idx_m.metrics_idx1);
        query_idx2 = query_idx2 ^ meta.flow_idx_m.metrics_idx2;
        flow_xor_idx2.write(meta.flow_idx_m.metrics_idx1,query_idx2);
        flow_xor_idx2.read(query_idx2,meta.flow_idx_m.metrics_idx2);
        query_idx2 = query_idx2 ^ meta.flow_idx_m.metrics_idx2;
        flow_xor_idx2.write(meta.flow_idx_m.metrics_idx2,query_idx2);
        flow_xor_idx2.read(query_idx2,meta.flow_idx_m.metrics_idx3);
        query_idx2 = query_idx2 ^ meta.flow_idx_m.metrics_idx2;
        flow_xor_idx2.write(meta.flow_idx_m.metrics_idx3,query_idx2);

        /* Update flow_xor_idx3 */
        flow_xor_idx3.read(query_idx3,meta.flow_idx_m.metrics_idx1);
        query_idx3 = query_idx3 ^ meta.flow_idx_m.metrics_idx3;
        flow_xor_idx3.write(meta.flow_idx_m.metrics_idx1,query_idx3);
        flow_xor_idx3.read(query_idx3,meta.flow_idx_m.metrics_idx2);
        query_idx3 = query_idx3 ^ meta.flow_idx_m.metrics_idx3;
        flow_xor_idx3.write(meta.flow_idx_m.metrics_idx2,query_idx3);
        flow_xor_idx3.read(query_idx3,meta.flow_idx_m.metrics_idx3);
        query_idx3 = query_idx3 ^ meta.flow_idx_m.metrics_idx3;
        flow_xor_idx3.write(meta.flow_idx_m.metrics_idx3,query_idx3);

        /*Update flow id*/
        //flowID_t flow_id = 0;
       // bit<104> flow_id = 0;
        bit<8>  protocol = 0;
        bit<32> srcAddr = 0;
        bit<32> dstAddr = 0;
        bit<16> srcPort = 0;
        bit<16> dstPort = 0;
        flow_xor_proto.read(protocol,meta.flow_idx_m.metrics_idx1);
        flow_xor_srcAddr.read(srcAddr,meta.flow_idx_m.metrics_idx1);
        flow_xor_dstAddr.read(dstAddr,meta.flow_idx_m.metrics_idx1);
        flow_xor_srcPort.read(srcPort,meta.flow_idx_m.metrics_idx1);
        flow_xor_dstPort.read(dstPort,meta.flow_idx_m.metrics_idx1);
        protocol = protocol ^ meta.flow_m.flow_id[7:0];
        srcAddr = srcAddr ^ meta.flow_m.flow_id[103:72];
        dstAddr = dstAddr ^ meta.flow_m.flow_id[71:40];
        srcPort = srcPort ^ meta.flow_m.flow_id[39:24];
        dstPort = dstPort ^ meta.flow_m.flow_id[23:8];
        flow_xor_proto.write(meta.flow_idx_m.metrics_idx1,protocol);
        flow_xor_srcAddr.write(meta.flow_idx_m.metrics_idx1,srcAddr);
        flow_xor_dstAddr.write(meta.flow_idx_m.metrics_idx1,dstAddr);
        flow_xor_srcPort.write(meta.flow_idx_m.metrics_idx1,srcPort);
        flow_xor_dstPort.write(meta.flow_idx_m.metrics_idx1,dstPort);

        flow_xor_proto.read(protocol,meta.flow_idx_m.metrics_idx2);
        flow_xor_srcAddr.read(srcAddr,meta.flow_idx_m.metrics_idx2);
        flow_xor_dstAddr.read(dstAddr,meta.flow_idx_m.metrics_idx2);
        flow_xor_srcPort.read(srcPort,meta.flow_idx_m.metrics_idx2);
        flow_xor_dstPort.read(dstPort,meta.flow_idx_m.metrics_idx2);
        protocol = protocol ^ meta.flow_m.flow_id[7:0];
        srcAddr = srcAddr ^ meta.flow_m.flow_id[103:72];
        dstAddr = dstAddr ^ meta.flow_m.flow_id[71:40];
        srcPort = srcPort ^ meta.flow_m.flow_id[39:24];
        dstPort = dstPort ^ meta.flow_m.flow_id[23:8];
        flow_xor_proto.write(meta.flow_idx_m.metrics_idx2,protocol);
        flow_xor_srcAddr.write(meta.flow_idx_m.metrics_idx2,srcAddr);
        flow_xor_dstAddr.write(meta.flow_idx_m.metrics_idx2,dstAddr);
        flow_xor_srcPort.write(meta.flow_idx_m.metrics_idx2,srcPort);
        flow_xor_dstPort.write(meta.flow_idx_m.metrics_idx2,dstPort);

        flow_xor_proto.read(protocol,meta.flow_idx_m.metrics_idx3);
        flow_xor_srcAddr.read(srcAddr,meta.flow_idx_m.metrics_idx3);
        flow_xor_dstAddr.read(dstAddr,meta.flow_idx_m.metrics_idx3);
        flow_xor_srcPort.read(srcPort,meta.flow_idx_m.metrics_idx3);
        flow_xor_dstPort.read(dstPort,meta.flow_idx_m.metrics_idx3);
        protocol = protocol ^ meta.flow_m.flow_id[7:0];
        srcAddr = srcAddr ^ meta.flow_m.flow_id[103:72];
        dstAddr = dstAddr ^ meta.flow_m.flow_id[71:40];
        srcPort = srcPort ^ meta.flow_m.flow_id[39:24];
        dstPort = dstPort ^ meta.flow_m.flow_id[23:8];
        flow_xor_proto.write(meta.flow_idx_m.metrics_idx3,protocol);
        flow_xor_srcAddr.write(meta.flow_idx_m.metrics_idx3,srcAddr);
        flow_xor_dstAddr.write(meta.flow_idx_m.metrics_idx3,dstAddr);
        flow_xor_srcPort.write(meta.flow_idx_m.metrics_idx3,srcPort);
        flow_xor_dstPort.write(meta.flow_idx_m.metrics_idx3,dstPort);

        /*flow_id = flow_id ^ meta.flow_m.flow_id[31:0];
        flow_xor_id.write(meta.flow_idx_m.metrics_idx1,flow_id);

        flow_xor_id.read(flow_id,meta.flow_idx_m.metrics_idx2);
        flow_id = flow_id ^ meta.flow_m.flow_id[31:0];
        flow_xor_id.write(meta.flow_idx_m.metrics_idx2,flow_id);


        flow_xor_id.read(flow_id,meta.flow_idx_m.metrics_idx3);
        flow_id = flow_id ^ meta.flow_m.flow_id[31:0];
        flow_xor_id.write(meta.flow_idx_m.metrics_idx3,flow_id);*/
    }

    action update_flow_track() {

        /* Update ctr_packets */
        ctr_packets.count(meta.flow_idx_m.metrics_idx1);
        ctr_packets.count(meta.flow_idx_m.metrics_idx2);
        ctr_packets.count(meta.flow_idx_m.metrics_idx3);

        /*ctr_packets.read(meta.flow_m.ctr_packets,meta.flow_idx_m.metrics_idx1);
        ctr_packets.write(meta.flow_idx_m.metrics_idx1,meta.flow_m.ctr_packets+1);
        ctr_packets.read(meta.flow_m.ctr_packets,meta.flow_idx_m.metrics_idx2);
        ctr_packets.write(meta.flow_idx_m.metrics_idx2,meta.flow_m.ctr_packets+1);
        ctr_packets.read(meta.flow_m.ctr_packets,meta.flow_idx_m.metrics_idx3);
        ctr_packets.write(meta.flow_idx_m.metrics_idx3,meta.flow_m.ctr_packets+1);*/
    }

    /*************************/

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table idps_icmp_ternary {
        key = {
            hdr.ipv4.srcAddr: ternary;
            hdr.ipv4.dstAddr: ternary;
        }
        actions = {
            mark_as_normal;
            mark_as_suspicious;
            NoAction;
        }
        size = 1024;
        default_action = mark_as_normal();
    }

    table idps_udp_ternary {
        key = {
            hdr.ipv4.srcAddr: ternary;
            hdr.ipv4.dstAddr: ternary;
            hdr.udp.srcPort:  ternary;
            hdr.udp.dstPort:  ternary;
        }
        actions = {
            mark_as_normal;
            mark_as_suspicious;
            NoAction;
        }
        size = 1024;
        default_action = mark_as_normal();
    }

    table idps_tcp_ternary {
        key = {
            hdr.ipv4.srcAddr: ternary;
            hdr.ipv4.dstAddr: ternary;
            hdr.tcp.srcPort:  ternary;
            hdr.tcp.dstPort:  ternary;
        }
        actions = {
            mark_as_normal;
            mark_as_suspicious;
            NoAction;
        }
        size = 1024;
        default_action = mark_as_normal();
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
        //counters = flow_stats;
    }

    apply {
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0){
            if (hdr.icmp.isValid()) {
                idps_icmp_ternary.apply();
            } else {
                if (hdr.udp.isValid()) {
                    idps_udp_ternary.apply();
                } else {
                    if (hdr.tcp.isValid()) {
                        idps_tcp_ternary.apply();
                    }
                }
            }
            if (meta.state_m.state == NORMAL_STATE) {
                ctr_normal.count(1);
            }
            if (meta.state_m.state == MALICIOUS_STATE) {
                ctr_suspicious.count(2);
                drop();
            }

            /************MONITOR*************/
            if (hdr.udp.isValid()) {
                    check_flow_track(hdr.udp.srcPort,hdr.udp.dstPort);
                    if (meta.flow_idx_m.is_stored == 0) {
                        create_flow_track();
                    }
                    update_flow_track();
            } else {
               if (hdr.tcp.isValid()) {
                    check_flow_track(hdr.tcp.srcPort,hdr.tcp.dstPort);
                    if (meta.flow_idx_m.is_stored == 0) {
                        create_flow_track();
                    }
                    update_flow_track();
                }
            }

            /********************************/

            ipv4_lpm.apply();
        }else{
            drop();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
