import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  reactStrictMode: true,
  allowedDevOrigins: ["bastionflow.localhost", "*.bastionflow.localhost"],
  poweredByHeader: false,
  // Disable streaming metadata: in Next 16 dev/Turbopack it can produce
  // MetadataWrapper hydration mismatches in this containerized setup.
  htmlLimitedBots: /.*/,
};

export default nextConfig;
