#!/usr/bin/env bash
set -euo pipefail
WALLET="prl1p5qqskp7gdvh6z2j39cmcldz8jvud0ccafyrgap0v8gt9&m4sx5xsq83puw"
WORKER="${2:-cmp40hx}"
POOL="d{3-:pearl-sg1.luckypool.io:3360}"
cd /root/pearl_f2pool/python
exec python3 miner_capi.py --wallet "$WALLET" --worker "$WORKER" --pool "$POOL"
