/** @type {import('next').NextConfig} */
const nextConfig = {
  // Disable image optimization — saves RAM on Windows
  images: { unoptimized: true },

  // Disable source maps in dev — major RAM saver
  productionBrowserSourceMaps: false,

  // Disable telemetry
  telemetry: false,

  // Proxy API calls to Flask
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: "http://localhost:5050/api/:path*",
      },
    ];
  },

  // Reduce webpack memory usage
  webpack: (config, { dev }) => {
    if (dev) {
      config.watchOptions = {
        poll: 2000,          // poll every 2s instead of inotify (fixes Windows crashes)
        aggregateTimeout: 500,
        ignored: /node_modules/,
      };
      // Limit parallel chunk processing
      config.parallelism = 1;
    }
    return config;
  },
};

module.exports = nextConfig;
