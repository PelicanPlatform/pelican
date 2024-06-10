/** @type {import('next').NextConfig} */
let nextConfig = {
    output: process.env.NODE_ENV === "development" ? "standalone" : 'export',
    basePath: "/view",
    trailingSlash: true,
    images: { unoptimized: true }
}

if(process.env.NODE_ENV === "development") {
    const withBundleAnalyzer = require('@next/bundle-analyzer')({
        enabled: process.env.ANALYZE === 'true',
    })
    nextConfig = withBundleAnalyzer(nextConfig)
}

module.exports = nextConfig
