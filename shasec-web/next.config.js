/** @type {import('next').NextConfig} */
const API = process.env.SHAAPI_URL || 'http://localhost:8000';

// Proxy /backend/* (same-origin, called by the browser) to the shaapi API.
// Same-origin means no CORS to configure on the backend.
const nextConfig = {
  async rewrites() {
    return [{ source: '/backend/:path*', destination: `${API}/api/v1/:path*` }];
  },
};

module.exports = nextConfig;
