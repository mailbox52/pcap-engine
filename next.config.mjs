/** @type {import('next').NextConfig} */
const nextConfig = {
  webpack(config) {
    // Spec requirement: Wasm support enabled under Webpack 5 experiments.
    config.experiments = { ...config.experiments, asyncWebAssembly: true };
    return config;
  },
};

export default nextConfig;
