<template>
  <div class="page-container">
    <h1 class="page-title">Video</h1>

    <div class="video-card">
      <div class="video-frame">
        <video
          ref="video"
          class="video-el"
          :class="{ hidden: status !== 'playing' }"
          controls
          autoplay
          muted
          playsinline
        ></video>

        <div v-if="status !== 'playing'" class="overlay">
          <template v-if="status === 'offline'">
            <i class="fas fa-video-slash overlay-icon"></i>
            <p class="overlay-title">Waiting for the camera&hellip;</p>
            <p class="overlay-text">
              The stream starts on demand and should appear within a few seconds. If it
              doesn't, make sure a camera is connected and that <code>enabled = true</code>
              under <code>[hls]</code> in the <strong>rtsp-server</strong> config on the
              <router-link to="/services-page">Services</router-link> page.
            </p>
            <p class="overlay-hint">Watching for the stream&hellip;</p>
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
import Hls from 'hls.js';

// Served by nginx straight from the rtsp-server tmpfs output dir.
const STREAM_URL = '/video/hls/stream.m3u8';
// How long to wait before re-probing when the playlist isn't up yet.
const RETRY_MS = 4000;

// While the page is open we heartbeat the gateway, which keeps a lease fresh so
// rtsp-server runs the camera + HLS restream only while someone is watching.
const KEEPALIVE_URL = '/api/video/keepalive';
const STOP_URL = '/api/video/stop';
const KEEPALIVE_MS = 3000;

export default {
  name: 'VideoPage',
  data() {
    return {
      status: 'connecting', // connecting | playing | offline | error
      errorText: '',
      hls: null,
      retryTimer: null,
      keepaliveTimer: null
    };
  },
  mounted() {
    // Only stream while the page is actually visible. Starting here rather than on a
    // hidden/background tab is what makes the camera run "only when on the page".
    document.addEventListener('visibilitychange', this.onVisibility);
    window.addEventListener('pagehide', this.onPageHide);
    if (!document.hidden) {
      this.startViewing();
    }
  },
  beforeUnmount() {
    document.removeEventListener('visibilitychange', this.onVisibility);
    window.removeEventListener('pagehide', this.onPageHide);
    this.stopViewing();
  },
  methods: {
    start() {
      this.teardown();
      this.status = 'connecting';

      const video = this.$refs.video;
      if (!video) return;

      if (Hls.isSupported()) {
        // We drive reconnect ourselves (the playlist may not exist yet), so disable
        // hls.js's own manifest retry and treat a fatal network error as "offline".
        const hls = new Hls({
          lowLatencyMode: true,
          liveSyncDurationCount: 2,
          manifestLoadingMaxRetry: 0,
          levelLoadingMaxRetry: 2
        });
        this.hls = hls;

        hls.on(Hls.Events.MANIFEST_PARSED, () => {
          video.play().catch(() => {});
        });
        hls.on(Hls.Events.FRAG_BUFFERED, () => {
          this.status = 'playing';
        });
        hls.on(Hls.Events.ERROR, (event, data) => {
          if (!data.fatal) return;

          switch (data.type) {
            case Hls.ErrorTypes.NETWORK_ERROR:
              // Most often the playlist 404s because HLS is disabled or the stream
              // hasn't produced its first segment yet.
              this.goOffline();
              break;
            case Hls.ErrorTypes.MEDIA_ERROR:
              hls.recoverMediaError();
              break;
            default:
              this.fail('Could not play the video stream.');
          }
        });

        hls.loadSource(STREAM_URL);
        hls.attachMedia(video);

      } else if (video.canPlayType('application/vnd.apple.mpegurl')) {
        // Safari / iOS play HLS natively; no hls.js needed.
        video.src = STREAM_URL;
        video.addEventListener('loadeddata', this.onNativeLoaded, { once: true });
        video.addEventListener('error', this.onNativeError, { once: true });
        video.play().catch(() => {});

      } else {
        this.fail('This browser cannot play HLS video.');
      }
    },

    onNativeLoaded() {
      this.status = 'playing';
    },
    onNativeError() {
      this.goOffline();
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
      if (this.hls) {
        this.hls.destroy();
        this.hls = null;
      }
      const video = this.$refs.video;
      if (video) {
        video.removeEventListener('loadeddata', this.onNativeLoaded);
        video.removeEventListener('error', this.onNativeError);
        video.removeAttribute('src');
        video.load();
      }
    },

    // --- viewer presence: keep the camera/HLS running only while this page is open ---

    startViewing() {
      this.startKeepalive();
      this.start();
    },
    // Hidden tab, in-app navigation, or close: release the stream and stop playback so
    // the camera isn't held open for a page nobody is looking at.
    stopViewing() {
      this.stopKeepalive();
      this.sendStop();
      this.teardown();
      this.status = 'connecting';
    },

    startKeepalive() {
      if (this.keepaliveTimer) return;
      this.sendKeepalive();
      this.keepaliveTimer = setInterval(this.sendKeepalive, KEEPALIVE_MS);
    },
    stopKeepalive() {
      if (this.keepaliveTimer) {
        clearInterval(this.keepaliveTimer);
        this.keepaliveTimer = null;
      }
    },
    sendKeepalive() {
      // rtsp-server brings HLS up within ~1s of the first beat; the retry loop above
      // then picks up the stream once the first segments appear.
      fetch(KEEPALIVE_URL, { method: 'POST' }).catch(() => {});
    },
    sendStop() {
      // sendBeacon still delivers during page unload, where a fetch would be cancelled.
      if (navigator.sendBeacon) {
        navigator.sendBeacon(STOP_URL);
      } else {
        fetch(STOP_URL, { method: 'POST', keepalive: true }).catch(() => {});
      }
    },

    onVisibility() {
      if (document.hidden) {
        this.stopViewing();
      } else {
        this.startViewing();
      }
    },
    onPageHide() {
      this.stopViewing();
    }
  }
};
</script>

<style scoped>
.page-container {
  display: flex;
  flex-direction: column;
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
  padding: 20px;
}

.page-title {
  font-size: 2rem;
  font-weight: 600;
  color: var(--ark-color-black);
  margin: 0;
  text-align: center;
}

.video-card {
  margin-top: 24px;
  background-color: var(--ark-color-white);
  border-radius: 8px;
  box-shadow: 0 2px 10px var(--ark-color-black-shadow);
  overflow: hidden;
}

/* 16:9 responsive frame */
.video-frame {
  position: relative;
  width: 100%;
  padding-top: 56.25%;
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

.overlay-text code {
  background-color: rgba(255, 255, 255, 0.15);
  padding: 1px 5px;
  border-radius: 4px;
  font-family: monospace;
}

.overlay-text a {
  color: var(--ark-color-green);
  text-decoration: none;
  font-weight: 600;
}

.overlay-text a:hover {
  text-decoration: underline;
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
