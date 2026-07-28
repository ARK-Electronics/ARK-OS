// vue.config.js
module.exports = {
  devServer: {
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
        pathRewrite: { '^/flight-review': '' }
      }
    }
  }
}
