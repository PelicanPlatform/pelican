/** @type {import('next').NextConfig} */
let nextConfig = {
  output: 'export',
  basePath: '/view',
  trailingSlash: true,
  images: { unoptimized: true },
};

const withBundleAnalyzer = require('@next/bundle-analyzer')({
  enabled: process.env.ANALYZE === 'true',
});
nextConfig = withBundleAnalyzer(nextConfig);

module.exports = nextConfig;
