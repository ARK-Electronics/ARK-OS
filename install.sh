#!/bin/bash
OUTPUT_FILE="output.txt"
pushd . &>/dev/null
cd "$(dirname "$0")"
./tools/install_software.sh 2>&1 | while IFS= read -r line; do
    echo "$(date +"[%H:%M:%S]") $line"
done | tee ${OUTPUT_FILE}
popd &>/dev/null
