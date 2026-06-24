#!/bin/bash

# Stream a few frames from each CSI camera to confirm it captures.
# Logic lifted from the jetson_test.sh check_cameras() function.
# Usage: ./check_cameras.sh [num_cameras]   (default 4)
# Returns: 0 if every camera streams, 1 if any camera fails.

TOTAL_CAMERAS="${1:-4}"  # number of CSI cameras to test
STREAM_COUNT=25          # frames to capture per camera

status=0
for ((i = 0; i < TOTAL_CAMERAS; i++)); do
    echo "Testing /dev/video$i:"
    # Capture frames to /dev/null and analyze what v4l2-ctl reports.
    output=$(v4l2-ctl --device=/dev/video$i --stream-mmap --stream-count=$STREAM_COUNT --stream-to=/dev/null 2>&1)

    if [[ $output == *'VIDIOC_STREAMON returned -1'* ]]; then
        echo "Camera /dev/video$i: ERROR detected."
        echo "$output" | grep -i error  # surface the error lines
        status=1
    elif [[ $output == *'fps'* ]]; then
        echo "Camera /dev/video$i: SUCCESS - $(echo "$output" | grep -o '[0-9]*\.[0-9]* fps')"
    else
        echo "Camera /dev/video$i: FAILED to confirm status."
        status=1
    fi
done

exit $status
