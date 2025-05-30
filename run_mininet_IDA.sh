// File: scripts/compile.sh
#!/bin/bash
p4c --target bmv2 --arch v1model ../p4src/p4_ida.p4 -o ../config/p4_ida.json

// File: scripts/run_mininet.sh
#!/bin/bash
sudo mn --custom ../topology/p4ida_topology.py --topo p4idatopo --controller remote