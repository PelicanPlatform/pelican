/** @type {import('next').NextConfig} */
const path = require('path');

let nextConfig = {
  output: 'export',
  basePath: '/view',
  trailingSlash: true,
  images: { unoptimized: true },
  // Pin tracing root to this app so Next.js does not walk the monorepo
  // (wrong root causes huge memory use and OOM / exit 137 in dev containers).
  outputFileTracingRoot: path.join(__dirname),
};

const withBundleAnalyzer = require('@next/bundle-analyzer')({
  enabled: process.env.ANALYZE === 'true',
});
nextConfig = withBundleAnalyzer(nextConfig);

module.exports = nextConfig;
