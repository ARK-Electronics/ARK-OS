// vue.config.js
module.exports = {
  devServer: {
    // The dev server gzips responses by default, and its compression middleware
    // buffers until it has enough bytes -- which for an SSE stream is never.
    // Every /api/.../stream and /events endpoint hangs at readyState 0 under
    // `npm run serve` with it on. nginx does not do this in production.
    compress: false,
    proxy: {
      // All API requests go through the Express server
      '/api': {
        target: 'http://localhost:3000',
        changeOrigin: true
      },
      // nginx serves this in production; the Logs page links plots here.
      '/flight-review': {
        target: 'http://localhost:5006',
        changeOrigin: true,
        // Bokeh's plot page opens a websocket under this prefix.
        ws: true,
        pathRewrite: { '^/flight-review': '' }
      }
    }
  }
}
