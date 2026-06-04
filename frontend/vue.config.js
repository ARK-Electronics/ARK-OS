// vue.config.js
module.exports = {
  devServer: {
    proxy: {
      // All API requests go through the Express server
      '/api': {
        target: 'http://localhost:3000',
        changeOrigin: true
      },
      // Unified Socket.IO connections for all services
      '/socket.io': {
        target: 'http://localhost:3000',
        changeOrigin: true,
        ws: true
      }
    }
  }
}
