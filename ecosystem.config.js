const config = require('./config.json');

module.exports = {
  apps : [{
    name: config.pm2Name,
    exec_mode: "cluster",
    instances: config.pm2Instances,
    script: 'dist/main.js',
  }],
};
