# P4-IDA: P4-Enabled Intrusion Detection Application

## Overview
A P4-programmed system that detects IoT anomalies based on traffic patterns. Integrates with BMv2, Mininet, and a custom Python controller.

## Structure
- `p4src/`: P4 program.
- `scripts/`: Compilation and launch scripts.
- `topology/`: Mininet topology file.
- `config/`: JSON entries for BMv2 runtime.
- `controller/`: gRPC controller using p4runtime.

## Run Instructions
```bash
cd scripts
./compile.sh
./run_mininet.sh
```

## Load Controller
```bash
cd controller
python3 controller.py
```

## Requirements
- P4C compiler
- BMv2 and PI/P4Runtime
- Mininet
- Python `p4runtime_lib`
