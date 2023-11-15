const config = require('./config.json');

module.exports = {
  apps : [{
    name: config.pm2Name,
    exec_mode: "cluster",
    instances: config.pm2Instances,
    script: 'dist/main.js',
    merge_logs: true,
    autorestart: true,
    exp_backoff_restart_delay: 100,
    watch: false,
    time: true,
    env: {
      "NODE_PORT": config.apiPort,
      "PORT": config.apiPort
    }
  }],
};
