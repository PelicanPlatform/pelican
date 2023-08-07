/** @type {import('next').NextConfig} */
const nextConfig = {
    output: process.env.NODE_ENV == "dev" ? "standalone" : 'export',
    basePath: '/view',
    trailingSlash: true,
    images: { unoptimized: true }
}


module.exports = nextConfig
