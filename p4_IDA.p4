// Directory Structure:
// P4-IDA/
// ├── README.md
// ├── topology/
// │   └── p4ida_topology.py
// ├── p4src/
// │   └── p4_ida.p4
// ├── scripts/
// │   ├── compile.sh
// │   └── run_mininet.sh
// ├── config/
// │   └── ida_runtime.json
// └── controller/
//     └── controller.py

// File: p4src/p4_ida.p4

#include <core.p4>

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    ipv4Addr_t srcAddr;
    ipv4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  reserved;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata_t {
    bit<32> pkt_len;
    bit<32> total_flow_count;
    bit<32> total_byte_count;
}

parser ParserImpl(packet_in pkt, out headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
}

table state_table {
    key = {
        hdr.ipv4.srcAddr: exact;
        hdr.ipv4.dstAddr: exact;
        hdr.tcp.srcPort: exact;
        hdr.tcp.dstPort: exact;
    }
    actions = {
        update_flow_state;
        detect_anomaly;
        drop_packet;
    }
    size = 1024;
    default_action = update_flow_state;
}

action update_flow_state() {
    meta.total_flow_count += 1;
    meta.total_byte_count += meta.pkt_len;
}

action detect_anomaly() {
    if (meta.total_flow_count > 1000 || meta.total_byte_count > 1000000) {
        mark_to_drop();
    }
}

action drop_packet() {
    mark_to_drop();
}

control IngressImpl(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    apply {
        meta.pkt_len = standard_metadata.packet_length;
        state_table.apply();
    }
}

control EgressImpl(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    apply {}
}

control DeparserImpl(packet_out pkt, in headers_t hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
    }
}

control PipelineMain(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    IngressImpl();
    EgressImpl();
    DeparserImpl();
}
