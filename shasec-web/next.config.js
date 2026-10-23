/** @type {import('next').NextConfig} */
// The browser never talks to the API directly: route handlers under /api/*
// (app/api) hold the session in httpOnly cookies and forward to SHAAPI_URL
// server-side, attaching the Bearer token. See lib/server/backend.ts.
const nextConfig = {
  poweredByHeader: false,
  // Self-contained server bundle for the Docker image (see Dockerfile).
  output: 'standalone',
};

module.exports = nextConfig;
