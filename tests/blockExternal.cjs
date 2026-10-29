const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const tls = require('node:tls');

function deny() {
  process.stderr.write('TEST BLOCKED AN OUTBOUND CONNECTION\n');
  process.exit(97);
}

for (const module of [http, https]) {
  module.request = deny;
  module.get = deny;
}
net.connect = deny;
net.createConnection = deny;
tls.connect = deny;
global.fetch = deny;
