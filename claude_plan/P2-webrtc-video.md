# P2: WebRTC Video in UI + UVC Camera Support

## Problem

The rtsp-server currently only supports CSI cameras via GStreamer. Users with USB cameras
(UVC devices) cannot stream video. Additionally, the ARK UI has no video page — users must
use a separate RTSP client (like VLC) to view the stream.

WebRTC would allow video to be viewed directly in the browser without plugins or external
applications.

## Solution

Two improvements:
1. **UVC camera support** in rtsp-server — Add V4L2 source pipeline for USB cameras
2. **WebRTC streaming** — Add a WebRTC endpoint so the browser can receive video directly

### Architecture

```
Camera (CSI/UVC) → GStreamer → rtsp-server → RTSP stream (existing)
                                           → WebRTC stream (new)

Browser → ARK UI → WebRTC JS client → rtsp-server WebRTC endpoint
```

## Files to Modify

### rtsp-server (C++ submodule, ARK-owned)

| File | Change |
|------|--------|
| `services/rtsp-server/rtsp-server/src/main.cpp` | Add V4L2 pipeline, WebRTC support |
| `services/rtsp-server/rtsp-server/config.toml` | Add `source_type` (csi/uvc/auto) |
| `services/rtsp-server/rtsp-server/CMakeLists.txt` | Add GStreamer WebRTC dependencies |

### Frontend (ARK UI)

| File | Change |
|------|--------|
| New: `frontend/ark-ui/ark-ui/src/views/VideoView.vue` | Video page with WebRTC player |
| `frontend/ark-ui/ark-ui/src/router/index.js` | Add /video route |
| `frontend/ark-ui/ark-ui/src/components/Sidebar.vue` (or equivalent) | Add Video nav link |

### Packaging

| File | Change |
|------|--------|
| `packaging/packages.yaml` | Add GStreamer WebRTC dependencies to rtsp-server |
| `frontend/ark-proxy.conf` or `ark-ui.nginx` | Add WebSocket proxy for WebRTC signaling |

## Implementation Steps

### Step 1: Add UVC camera detection

Add auto-detection of camera type in rtsp-server:

```cpp
// Detect available cameras
bool has_csi_camera();    // Check /dev/video0 with V4L2 caps
bool has_uvc_camera();    // Check /dev/video* for UVC devices

std::string get_pipeline(const std::string& source_type) {
    if (source_type == "csi" || (source_type == "auto" && has_csi_camera())) {
        return "nvarguscamerasrc ! video/x-raw(memory:NVMM),width=1920,height=1080 ! ...";
    } else if (source_type == "uvc" || (source_type == "auto" && has_uvc_camera())) {
        return "v4l2src device=/dev/video0 ! video/x-raw,width=1280,height=720 ! ...";
    } else {
        return "videotestsrc ! ...";  // Test pattern fallback
    }
}
```

### Step 2: Update rtsp-server config

```toml
# config.toml
[camera]
source_type = "auto"    # "csi", "uvc", "auto", "test"
device = "/dev/video0"  # For UVC, auto-detected if not set
width = 1280
height = 720
framerate = 30
```

### Step 3: Add WebRTC support via GStreamer

Use GStreamer's `webrtcbin` element for WebRTC:

```cpp
// WebRTC pipeline
// camera → encoder → payloader → webrtcbin
auto pipeline = gst_parse_launch(
    "v4l2src ! videoconvert ! x264enc tune=zerolatency ! "
    "rtph264pay ! webrtcbin name=webrtc", nullptr);
```

Add a simple HTTP/WebSocket signaling endpoint for SDP exchange. This could be:
- A lightweight embedded HTTP server (cpp-httplib, already vendored in logloader)
- A separate signaling endpoint proxied through nginx

### Step 4: Create Video page in ARK UI

```vue
<!-- VideoView.vue -->
<template>
  <div class="video-page">
    <h2>Camera Stream</h2>
    <video ref="videoElement" autoplay playsinline muted></video>
    <div class="controls">
      <select v-model="selectedCamera">
        <option value="camera1">Camera 1</option>
      </select>
      <button @click="toggleStream">{{ streaming ? 'Stop' : 'Start' }}</button>
    </div>
  </div>
</template>

<script>
export default {
  data() {
    return { streaming: false, pc: null, selectedCamera: 'camera1' }
  },
  methods: {
    async toggleStream() {
      if (this.streaming) {
        this.pc?.close();
        this.streaming = false;
      } else {
        await this.startWebRTC();
      }
    },
    async startWebRTC() {
      this.pc = new RTCPeerConnection();
      this.pc.ontrack = (event) => {
        this.$refs.videoElement.srcObject = event.streams[0];
      };
      // Exchange SDP with signaling server
      // ...
    }
  }
}
</script>
```

### Step 5: Add nginx proxy for WebRTC signaling

Add to nginx config:
```nginx
location /api/video/ws {
    proxy_pass http://127.0.0.1:5601;  # WebRTC signaling port
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}
```

### Step 6: Update packaging

Add WebRTC GStreamer dependencies:
```yaml
rtsp-server:
  depends:
    - libgstreamer1.0-0
    - libgstreamer-plugins-base1.0-0
    - gstreamer1.0-plugins-ugly
    - gstreamer1.0-rtsp
    - gstreamer1.0-nice          # ICE/STUN/TURN for WebRTC
    - gstreamer1.0-plugins-bad   # webrtcbin element
```

## Acceptance Criteria

- [ ] rtsp-server detects and streams from UVC cameras (`/dev/video*`)
- [ ] `config.toml` supports `source_type` = csi, uvc, auto, test
- [ ] Auto-detection correctly identifies CSI vs UVC cameras
- [ ] WebRTC stream viewable in Chrome/Firefox without plugins
- [ ] ARK UI has a Video page accessible from navigation
- [ ] Video page shows live stream with <500ms latency
- [ ] RTSP stream still works alongside WebRTC (existing clients unaffected)
- [ ] Works on both Jetson (CSI + UVC) and Pi (UVC)

## Dependencies

None — can be developed independently, but benefits from P0-path-migration being done
first so the config paths are correct.

## Effort Estimate

Large. This is a significant feature addition:
- UVC support in rtsp-server: 1-2 sessions
- WebRTC via GStreamer webrtcbin: 2-3 sessions (signaling is the complex part)
- Frontend Video page: 1 session
- Testing on actual hardware: 1-2 sessions
Total estimate: 5-8 sessions.
