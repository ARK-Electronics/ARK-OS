<template>
  <div class="page-container">
    <h1 class="page-title">Video</h1>

    <div class="video-card">
      <div ref="frame" class="video-frame">
        <video
          ref="video"
          class="video-el"
          :class="{ hidden: status !== 'playing' }"
          autoplay
          muted
          playsinline
        ></video>

        <!-- Live viewer chrome: a LIVE badge + fullscreen. No seek bar — this is a live
             WebRTC stream, not a scrubbable recording, and it always shows the latest frame. -->
        <div v-if="status === 'playing'" class="live-chrome">
          <span class="live-badge">
            <span class="live-dot"></span>LIVE
          </span>
          <button class="icon-btn" title="Fullscreen" @click="toggleFullscreen">
            <i class="fas fa-expand"></i>
          </button>
        </div>

        <!-- Camera picker: only shown when more than one camera is connected. Sits in
             the top-right and stays reachable whatever the stream status is, so you can
             switch source while it's still connecting. -->
        <div v-if="cameras.length > 1" class="camera-picker">
          <i class="fas fa-video"></i>
          <select
            :value="configured"
            :disabled="switching"
            title="Choose which camera the RTSP server streams"
            @change="onSelectCamera($event.target.value)"
          >
            <option value="">Auto ({{ autoLabel }})</option>
            <option v-for="cam in cameras" :key="cam.path" :value="cam.path" :title="cam.name">
              {{ cameraLabel(cam) }}
            </option>
          </select>
          <i v-if="switching" class="fas fa-spinner fa-spin"></i>
        </div>

        <div v-if="status !== 'playing'" class="overlay">
          <template v-if="status === 'offline'">
            <i class="fas fa-video-slash overlay-icon"></i>
            <p class="overlay-title">Waiting for the camera&hellip;</p>
            <p class="overlay-text">
              The stream starts on demand and should appear within a few seconds. If it
              doesn't, make sure a camera is connected.
            </p>
            <p class="overlay-hint">Reconnecting&hellip;</p>
          </template>

          <template v-else-if="status === 'error'">
            <i class="fas fa-triangle-exclamation overlay-icon"></i>
            <p class="overlay-title">Playback error</p>
            <p class="overlay-text">{{ errorText }}</p>
            <button class="retry-btn" @click="start">Retry</button>
          </template>

          <template v-else>
            <i class="fas fa-spinner fa-spin overlay-icon"></i>
            <p class="overlay-title">Connecting to stream&hellip;</p>
          </template>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
// go2rtc restreams the camera to the browser over WebRTC. We negotiate with its WHEP
// endpoint (nginx proxies /video/ to go2rtc): POST our SDP offer, get an SDP answer.
// Media then flows directly from the device — playback is ~sub-second and there is no
// buffer to drift, so no live-edge tracking is needed.
import CameraService from '../services/CameraService';

const WHEP_URL = '/video/api/webrtc?src=camera1';
// go2rtc opens the camera only while a client is connected, so the stream can take ~1s
// to appear after the page opens (camera + encoder spin up). Retry until it's up.
const RETRY_MS = 3000;
// Cap ICE gathering so a slow candidate can't hang the offer; LAN host candidates
// resolve well within this.
const ICE_GATHER_MS = 1500;
// Poll the camera list so a hotplugged camera (or the active one being unplugged)
// shows up in the picker without a page reload.
const CAMERA_POLL_MS = 5000;
// After switching cameras the rtsp-server restarts and go2rtc has to re-open the new
// source; give it a moment before re-negotiating so the first attempt doesn't 404.
const SWITCH_RECONNECT_MS = 2000;

export default {
  name: 'VideoPage',
  data() {
    return {
      status: 'connecting', // connecting | playing | offline | error
      errorText: '',
      pc: null,
      retryTimer: null,
      cameras: [],          // [{ path, index, name, type, selected }]
      configured: '',       // persisted [camera].device ("" = auto-select)
      switching: false,     // a select() round-trip + restart is in flight
      cameraPollTimer: null
    };
  },
  computed: {
    // Label for the auto option: the lowest-numbered camera the server would pick.
    autoLabel() {
      return this.cameras.length ? this.cameraLabel(this.cameras[0]) : 'lowest /dev/video';
    }
  },
  mounted() {
    // Only stream while the page is actually visible: hiding the tab tears the peer
    // connection down, which drops go2rtc's last consumer and releases the camera, so it
    // runs only while someone is watching.
    document.addEventListener('visibilitychange', this.onVisibility);
    window.addEventListener('pagehide', this.teardown);
    if (!document.hidden) {
      this.start();
    }
    this.fetchCameras();
    this.cameraPollTimer = setInterval(this.fetchCameras, CAMERA_POLL_MS);
  },
  beforeUnmount() {
    document.removeEventListener('visibilitychange', this.onVisibility);
    window.removeEventListener('pagehide', this.teardown);
    if (this.cameraPollTimer) clearInterval(this.cameraPollTimer);
    this.teardown();
  },
  methods: {
    async fetchCameras() {
      try {
        const { data } = await CameraService.getCameras();
        this.cameras = data.cameras || [];
        // Don't clobber the dropdown mid-switch; the optimistic value set in
        // onSelectCamera is authoritative until the restart settles.
        if (!this.switching) {
          this.configured = data.configured || '';
        }
      } catch (err) {
        // Camera-manager down or no cameras — leave the picker hidden, keep streaming.
        this.cameras = [];
      }
    },

    cameraLabel(cam) {
      const kind = cam.type === 'csi' ? 'CSI' : cam.type === 'usb' ? 'USB' : 'Camera';
      return `${kind} — ${cam.path}`;
    },

    async onSelectCamera(device) {
      if (device === this.configured) return;
      this.switching = true;
      const previous = this.configured;
      this.configured = device; // optimistic; reconciled by the next poll
      try {
        const { data } = await CameraService.selectCamera(device);
        if (data.status !== 'success') {
          this.configured = previous;
          alert(`Could not switch camera: ${data.message || 'unknown error'}`);
          return;
        }
        // rtsp-server is restarting on the new device — reconnect the stream shortly.
        this.teardown();
        this.status = 'connecting';
        this.retryTimer = setTimeout(this.start, SWITCH_RECONNECT_MS);
      } catch (err) {
        this.configured = previous;
        alert('Could not switch camera: request failed');
      } finally {
        this.switching = false;
        this.fetchCameras();
      }
    },

    async start() {
      this.teardown();
      this.status = 'connecting';

      const video = this.$refs.video;
      if (!video) return;

      let pc;
      try {
        pc = new RTCPeerConnection();
      } catch (err) {
        this.fail('This browser cannot play WebRTC video.');
        return;
      }
      this.pc = pc;

      // Receive-only: we play the camera, we don't send anything.
      pc.addTransceiver('video', { direction: 'recvonly' });

      pc.ontrack = (event) => {
        if (event.streams && event.streams[0]) {
          video.srcObject = event.streams[0];
          video.play().catch(() => {});
        }
      };

      pc.onconnectionstatechange = () => {
        if (this.pc !== pc) return;
        switch (pc.connectionState) {
        case 'connected':
          this.status = 'playing';
          break;
        case 'failed':
        case 'disconnected':
        case 'closed':
          // Lost the stream (camera unplugged, go2rtc restarted). Drop back to the retry
          // loop, which re-negotiates once it's available again.
          this.goOffline();
          break;
        }
      };

      try {
        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        // go2rtc's WHEP answer is non-trickle, so send a complete offer.
        await this.waitForIceGathering(pc);
        if (this.pc !== pc) return; // teardown raced the await

        const resp = await fetch(WHEP_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/sdp' },
          body: pc.localDescription.sdp
        });

        // 404/5xx means go2rtc has no stream yet (camera still starting, or source
        // down). Treat it as "not up" and retry.
        if (!resp.ok) {
          this.goOffline();
          return;
        }

        const text = await resp.text();
        if (this.pc !== pc) return;
        // go2rtc's WHEP endpoint answers with raw SDP (application/sdp); tolerate a
        // JSON { type, sdp } body too, in case the API shape differs by version.
        let answerSdp = text;
        if (text.trimStart().startsWith('{')) {
          try { answerSdp = JSON.parse(text).sdp; } catch (e) { /* keep raw text */ }
        }
        await pc.setRemoteDescription({ type: 'answer', sdp: answerSdp });
      } catch (err) {
        this.goOffline();
      }
    },

    // Resolve once ICE gathering completes, or after ICE_GATHER_MS so a stalled
    // candidate can't block the offer forever.
    waitForIceGathering(pc) {
      if (pc.iceGatheringState === 'complete') return Promise.resolve();
      return new Promise((resolve) => {
        let settled = false;
        const finish = () => {
          if (settled) return;
          settled = true;
          pc.removeEventListener('icegatheringstatechange', onChange);
          resolve();
        };
        const onChange = () => {
          if (pc.iceGatheringState === 'complete') finish();
        };
        pc.addEventListener('icegatheringstatechange', onChange);
        setTimeout(finish, ICE_GATHER_MS);
      });
    },

    toggleFullscreen() {
      const frame = this.$refs.frame;
      if (!frame) return;
      if (document.fullscreenElement) {
        document.exitFullscreen().catch(() => {});
      } else {
        frame.requestFullscreen().catch(() => {});
      }
    },

    goOffline() {
      this.teardown();
      this.status = 'offline';
      this.retryTimer = setTimeout(this.start, RETRY_MS);
    },
    fail(msg) {
      this.teardown();
      this.status = 'error';
      this.errorText = msg;
    },

    teardown() {
      if (this.retryTimer) {
        clearTimeout(this.retryTimer);
        this.retryTimer = null;
      }
      if (this.pc) {
        this.pc.ontrack = null;
        this.pc.onconnectionstatechange = null;
        this.pc.close();
        this.pc = null;
      }
      const video = this.$refs.video;
      if (video) {
        video.srcObject = null;
      }
    },

    onVisibility() {
      if (document.hidden) {
        this.teardown();
        this.status = 'connecting';
      } else {
        this.start();
      }
    }
  }
};
</script>

<style scoped>
/* Fill the viewport so the live view is as large as it can be without ever pushing a
   page scrollbar: the title takes its natural height, the video frame takes the rest. */
.page-container {
  display: flex;
  flex-direction: column;
  width: 100%;
  max-width: 1600px;
  height: 100vh;
  /* Left-aligned (not centered): the Video route widens #app to the full viewport, so
     keep the frame beside the sidebar like the other pages instead of floating it in the
     middle of that full width. */
  margin: 0;
  padding: 16px 20px 20px;
  box-sizing: border-box;
}

.page-title {
  flex: 0 0 auto;
  font-size: 2rem;
  font-weight: 600;
  color: var(--ark-color-black);
  margin: 0 0 16px;
  text-align: center;
}

.video-card {
  flex: 1 1 auto;
  min-height: 0;
  display: flex;
  background-color: var(--ark-color-white);
  border-radius: 8px;
  box-shadow: 0 2px 10px var(--ark-color-black-shadow);
  overflow: hidden;
}

.video-frame {
  position: relative;
  flex: 1 1 auto;
  min-height: 0;
  width: 100%;
  background-color: #000;
}

.video-el,
.overlay {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
}

.video-el {
  object-fit: contain;
  background-color: #000;
}

.video-el.hidden {
  visibility: hidden;
}

/* --- camera picker --- */
.camera-picker {
  position: absolute;
  top: 14px;
  right: 14px;
  z-index: 2;
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 6px 10px;
  border-radius: 5px;
  background-color: rgba(0, 0, 0, 0.55);
  color: var(--ark-color-white);
  font-size: 0.85rem;
}

.camera-picker select {
  background-color: rgba(0, 0, 0, 0.35);
  color: var(--ark-color-white);
  border: 1px solid rgba(255, 255, 255, 0.3);
  border-radius: 4px;
  padding: 4px 6px;
  font-size: 0.85rem;
  cursor: pointer;
}

.camera-picker select:disabled {
  opacity: 0.6;
  cursor: default;
}

/* The native dropdown list renders with the UA's default colors; force dark text so
   options stay readable against the white menu background. */
.camera-picker option {
  color: var(--ark-color-black);
}

/* --- live chrome --- */
.live-chrome {
  position: absolute;
  inset: 0;
  pointer-events: none;
}

.live-badge {
  position: absolute;
  top: 14px;
  left: 14px;
  display: inline-flex;
  align-items: center;
  gap: 7px;
  padding: 5px 11px;
  border-radius: 4px;
  background-color: rgba(0, 0, 0, 0.55);
  color: var(--ark-color-white);
  font-size: 0.8rem;
  font-weight: 700;
  letter-spacing: 0.06em;
  user-select: none;
}

.live-dot {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  background-color: var(--ark-color-red);
}

.icon-btn {
  position: absolute;
  bottom: 14px;
  right: 14px;
  width: 38px;
  height: 38px;
  border: none;
  border-radius: 5px;
  background-color: rgba(0, 0, 0, 0.55);
  color: var(--ark-color-white);
  font-size: 1rem;
  cursor: pointer;
  pointer-events: auto;
  transition: background-color 0.1s ease-in-out;
}

.icon-btn:hover {
  background-color: rgba(0, 0, 0, 0.8);
}

.overlay {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  padding: 24px;
  color: var(--ark-color-white);
}

.overlay-icon {
  font-size: 2.5rem;
  margin-bottom: 12px;
  opacity: 0.85;
}

.overlay-title {
  font-size: 1.25rem;
  font-weight: 600;
  margin: 0 0 8px;
}

.overlay-text {
  max-width: 520px;
  margin: 0;
  line-height: 1.5;
  opacity: 0.9;
}

.overlay-hint {
  margin-top: 12px;
  font-size: 0.9rem;
  opacity: 0.7;
}

.retry-btn {
  margin-top: 16px;
  padding: 8px 20px;
  border: none;
  border-radius: 5px;
  background-color: var(--ark-color-green);
  color: var(--ark-color-white);
  font-weight: 600;
  cursor: pointer;
  transition: background-color 0.1s ease-in-out;
}

.retry-btn:hover {
  background-color: var(--ark-color-green-hover);
}
</style>
