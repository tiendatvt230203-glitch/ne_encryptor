#!/bin/sh
set -e
cd "$(dirname "$0")/.."
make
cd iface_life_harness
sudo ./iface-life-harness
