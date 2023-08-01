/** @type {import('next').NextConfig} */
const nextConfig = {
    output: process.env.NODE_ENV ? "standalone" : 'export',
    basePath: '/view',
    trailingSlash: true,
    images: { unoptimized: true }
}


module.exports = nextConfig
