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

        <!-- Live viewer chrome: only a LIVE badge + fullscreen. No seek bar: this is a
             live stream, not a scrubbable recording. -->
        <div v-if="status === 'playing'" class="live-chrome">
          <span class="live-badge" :class="{ behind: behindLive }" @click="jumpToLive">
            <span class="live-dot"></span>{{ behindLive ? 'GO LIVE' : 'LIVE' }}
          </span>
          <button class="icon-btn" title="Fullscreen" @click="toggleFullscreen">
            <i class="fas fa-expand"></i>
          </button>
        </div>

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
// How often to nudge playback back to the live edge.
const SYNC_MS = 2000;
// Seek to the live edge once we've drifted more than this far behind it (seconds).
// Big enough not to fight normal jitter; small enough that a stall can't leave us
// minutes behind, which is the whole "doesn't play the latest frame" complaint.
const MAX_DRIFT_S = 5;

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
      behindLive: false,
      hls: null,
      retryTimer: null,
      syncTimer: null,
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
        // Tuned for a live monitor: stay near the live edge, keep no back-buffer (so
        // there's nothing to scrub back through), and drive reconnect ourselves since
        // the playlist may 404 until the first segment lands.
        const hls = new Hls({
          lowLatencyMode: true,
          liveSyncDurationCount: 3,
          liveMaxLatencyDurationCount: 10,
          liveDurationInfinity: true,
          backBufferLength: 0,
          maxLiveSyncPlaybackRate: 1.5,
          manifestLoadingMaxRetry: 0,
          levelLoadingMaxRetry: 2
        });
        this.hls = hls;

        hls.on(Hls.Events.MANIFEST_PARSED, () => {
          video.play().catch(() => {});
        });
        // A playlist carrying #EXT-X-ENDLIST is a leftover VOD playlist from a previous
        // session (the restream stopped and finalized it). Playing it would start at
        // segment 0 with a full scrub bar — exactly the "not live" behavior. Treat it as
        // "not up yet" and retry until the fresh live playlist appears.
        hls.on(Hls.Events.LEVEL_LOADED, (event, data) => {
          if (data.details && data.details.live === false) {
            this.goOffline();
          }
        });
        hls.on(Hls.Events.FRAG_BUFFERED, () => {
          this.status = 'playing';
          this.syncToLive();
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

      this.startSync();
    },

    onNativeLoaded() {
      this.status = 'playing';
    },
    onNativeError() {
      this.goOffline();
    },

    // --- live-edge tracking: keep playback pinned to the latest frame ---

    startSync() {
      if (this.syncTimer) return;
      this.syncTimer = setInterval(this.syncToLive, SYNC_MS);
    },
    stopSync() {
      if (this.syncTimer) {
        clearInterval(this.syncTimer);
        this.syncTimer = null;
      }
    },
    // The live edge is hls.liveSyncPosition for hls.js, or the end of the seekable
    // range for native playback. If we've fallen too far behind (a stall, a hidden
    // tab, the encoder hiccuping), jump forward so the viewer sees "now".
    syncToLive() {
      const video = this.$refs.video;
      if (!video || this.status !== 'playing') return;

      let liveEdge = null;
      if (this.hls && this.hls.liveSyncPosition != null && isFinite(this.hls.liveSyncPosition)) {
        liveEdge = this.hls.liveSyncPosition;
      } else if (video.seekable.length) {
        liveEdge = video.seekable.end(video.seekable.length - 1);
      }
      if (liveEdge == null) return;

      const drift = liveEdge - video.currentTime;
      this.behindLive = drift > MAX_DRIFT_S;
      if (this.behindLive) {
        video.currentTime = liveEdge;
      }
      if (video.paused) {
        video.play().catch(() => {});
      }
    },
    jumpToLive() {
      const video = this.$refs.video;
      if (!video) return;
      if (this.hls && this.hls.liveSyncPosition != null && isFinite(this.hls.liveSyncPosition)) {
        video.currentTime = this.hls.liveSyncPosition;
      } else if (video.seekable.length) {
        video.currentTime = video.seekable.end(video.seekable.length - 1);
      }
      video.play().catch(() => {});
      this.behindLive = false;
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
      this.stopSync();
      this.behindLive = false;
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
/* Fill the viewport so the live view is as large as it can be without ever pushing a
   page scrollbar: the title takes its natural height, the video frame takes the rest. */
.page-container {
  display: flex;
  flex-direction: column;
  width: 100%;
  max-width: 1600px;
  height: 100vh;
  margin: 0 auto;
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
  pointer-events: auto;
  user-select: none;
}

.live-dot {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  background-color: var(--ark-color-red);
}

/* When behind, the badge becomes a "GO LIVE" button. */
.live-badge.behind {
  cursor: pointer;
  background-color: rgba(0, 0, 0, 0.75);
}

.live-badge.behind .live-dot {
  background-color: var(--ark-color-grey);
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
