'use strict';

const fs = require('fs');
const crypto = require('crypto');
const http = require('https');
const got = require('got');

const config = require('./config.json');

let server = http.createServer((req, res) => {
    res.writeHead(200, "OK");
    res.end("Hello World!");
});

server.listen(config.port);
