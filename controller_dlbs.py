// File: controller/controller.py
import json
import time
from p4runtime_lib.switch import ShutdownAllSwitchConnections
from p4runtime_lib.helper import P4InfoHelper
from p4runtime_lib.bmv2 import Bmv2SwitchConnection

p4info_helper = P4InfoHelper('build/p4_ida.p4.p4info.txt')
s1 = Bmv2SwitchConnection(name='s1', address='127.0.0.1:50051', device_id=0, proto_dump_file='logs/s1-p4runtime-requests.txt')
s1.MasterArbitrationUpdate()
s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path='build/p4_ida.json')

# Add match-action rule
table_entry = p4info_helper.buildTableEntry(
    table_name='state_table',
    match_fields={
        'hdr.ipv4.srcAddr': '10.0.0.1',
        'hdr.ipv4.dstAddr': '10.0.0.2',
        'hdr.tcp.srcPort': 1234,
        'hdr.tcp.dstPort': 80
    },
    action_name='detect_anomaly'
)
s1.WriteTableEntry(table_entry)
print("Rule installed on s1")

try:
    while True:
        time.sleep(2)
except KeyboardInterrupt:
    print("Shutting down.")
    ShutdownAllSwitchConnections()
