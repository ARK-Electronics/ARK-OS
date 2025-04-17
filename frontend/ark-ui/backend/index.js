// app.js
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const morgan = require('morgan');
const cors = require('cors');
const http = require('http');

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;

// Apply middleware that doesn't interfere with request body
app.use(morgan('dev')); // Logging for HTTP requests
app.use(cors());

// Configuration for our microservices (with default values)
const NETWORK_SERVICE_URL = process.env.NETWORK_SERVICE_URL || 'http://localhost:3001';
const SERVICE_MANAGER_URL = process.env.SERVICE_MANAGER_URL || 'http://localhost:3002';
const AUTOPILOT_SERVICE_URL = process.env.AUTOPILOT_SERVICE_URL || 'http://localhost:3003';
const SYSTEM_SERVICE_URL = process.env.SYSTEM_SERVICE_URL || 'http://localhost:3004';

console.log('Service URLs:');
console.log(`- NETWORK_SERVICE_URL: ${NETWORK_SERVICE_URL}`);
console.log(`- SERVICE_MANAGER_URL: ${SERVICE_MANAGER_URL}`);
console.log(`- AUTOPILOT_SERVICE_URL: ${AUTOPILOT_SERVICE_URL}`);
console.log(`- SYSTEM_SERVICE_URL: ${SYSTEM_SERVICE_URL}`);

app.use((req, res, next) => {
  console.log(`[${req.method}] ${req.originalUrl}`);
  next();
});

// Create an array to keep track of all websocket proxies
const wsProxies = [];

const createWsProxy = (path, target) => {
  const proxy = createProxyMiddleware({
    target: target,
    changeOrigin: true,
    ws: true,
    logLevel: 'debug',
    onError: (err, req, res) => {
      console.error(`WebSocket proxy error on ${path}: ${err.message}`);
      if (res.writeHead) {
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'WebSocket service unavailable' }));
      }
    }
  });

  app.use(path, proxy);
  wsProxies.push({ path, proxy });
};

// Create websocket proxies
createWsProxy('/socket.io/network-stats', NETWORK_SERVICE_URL);
createWsProxy('/socket.io/autopilot-firmware-upload', AUTOPILOT_SERVICE_URL);

server.on('upgrade', (req, socket, head) => {
  const matchingProxy = wsProxies.find(({ path }) => req.url.startsWith(path));
  if (matchingProxy) {
    matchingProxy.proxy.upgrade(req, socket, head);
  } else {
    socket.destroy();
  }
});

// Service proxy
app.use('/api/service', createProxyMiddleware({
  target: SERVICE_MANAGER_URL,
  changeOrigin: true,
  logLevel: 'debug',
  onError: (err, req, res) => {
    console.error(`Service proxy error: ${err.message}`);
    res.writeHead(502, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Service service unavailable' }));
  }
}));

// Network proxy
app.use('/api/network', createProxyMiddleware({
  target: NETWORK_SERVICE_URL,
  changeOrigin: true,
  logLevel: 'debug',
  onError: (err, req, res) => {
    console.error(`Network proxy error: ${err.message}`);
    res.writeHead(502, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Network service unavailable' }));
  }
}));

// Autopilot proxy
app.use('/api/autopilot', createProxyMiddleware({
  target: AUTOPILOT_SERVICE_URL,
  changeOrigin: true,
  logLevel: 'debug',
  onError: (err, req, res) => {
    console.error(`Autopilot service proxy error: ${err.message}`);
    res.writeHead(502, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Autopilot service unavailable' }));
  }
}));

// System proxy
app.use('/api/system', createProxyMiddleware({
  target: SYSTEM_SERVICE_URL,
  changeOrigin: true,
  logLevel: 'debug',
  onError: (err, req, res) => {
    console.error(`System service proxy error: ${err.message}`);
    res.writeHead(502, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'System service unavailable' }));
  }
}));

// NOW add body parsing middleware AFTER all proxies
app.use(express.json());

// Add body logging middleware after body parser
app.use((req, res, next) => {
  if (req.body && Object.keys(req.body).length > 0) {
    console.log(`Request body:`, req.body);
  }
  next();
});

// Health check endpoint and other non-proxy endpoints
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    services: {
      network: { url: NETWORK_SERVICE_URL },
      service: { url: SERVICE_MANAGER_URL },
      autopilot: { url: AUTOPILOT_SERVICE_URL },
      system: { url: SYSTEM_SERVICE_URL }
    }
  });
});

// Fallback route for API requests when services are down
app.use('/api/*', (req, res) => {
  res.status(503).json({
    error: 'Service Unavailable',
    message: 'The requested microservice is currently unavailable'
  });
});

// Error handling
app.use((err, req, res, next) => {
  console.error('Express error:', err.stack);
  res.status(500).json({
    error: 'Internal Server Error',
    message: err.message
  });
});

// Start the server
server.listen(PORT, () => {
  console.log(`API Gateway running on port ${PORT}`);
});

module.exports = { app, server };
