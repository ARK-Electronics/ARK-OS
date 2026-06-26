#!/bin/bash

# Stream a few frames from each CSI camera to confirm it captures.
# Logic lifted from the jetson_test.sh check_cameras() function.
# Usage: ./check_cameras.sh [num_cameras]   (default 4)
# Returns: 0 if every camera streams, 1 if any camera fails.
# Per camera prints one parseable line: "/dev/videoN: OK - <fps>" or "/dev/videoN: FAILED: <reason>".

TOTAL_CAMERAS="${1:-4}"  # number of CSI cameras to test
STREAM_COUNT=25          # frames to capture per camera

status=0
for ((i = 0; i < TOTAL_CAMERAS; i++)); do
    # Capture frames to /dev/null and parse what v4l2-ctl reports for this device.
    output=$(v4l2-ctl --device=/dev/video$i --stream-mmap --stream-count=$STREAM_COUNT --stream-to=/dev/null 2>&1)

    if [ ! -e "/dev/video$i" ] || [[ $output == *'Cannot open device'* ]] || [[ $output == *'No such file'* ]]; then
        echo "/dev/video$i: FAILED: not found"
        status=1
    elif [[ $output == *'fps'* ]]; then
        echo "/dev/video$i: OK - $(echo "$output" | grep -o '[0-9]*\.[0-9]* fps' | head -1)"
    else
        echo "/dev/video$i: FAILED: no frames"
        status=1
    fi
done

exit $status
