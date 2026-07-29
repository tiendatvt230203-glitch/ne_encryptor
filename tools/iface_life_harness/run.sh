#!/bin/sh
set -e
cd "$(dirname "$0")/../.."
make iface-life-harness
sudo ./iface-life-harness
