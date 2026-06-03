module.exports = {
  apps: [
    {
      name: "operation-ip-quality-platform",
      script: "server.js",
      env: {
        NODE_ENV: "production",
        PORT: process.env.PORT || 4173,
      },
      max_memory_restart: "300M",
    },
  ],
};

