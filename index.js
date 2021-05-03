'use strict';

const fs = require('fs');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const got = require('got');
const ws = require('ws');
const config = require('./config.json');

let authenticatedConnections = {};
let id_counter = 0;

let server = http.createServer((req, res) => {
    console.log(req.url);
    switch (req.url.substring(1)) {
        case "twitch/callback": {
            console.log("Twitch Callback!");
            if (req.method === 'POST') {

                let body = Buffer.from('');
                let firstChunk = true;
                req.on('data', chunk => {
                    if (firstChunk) {
                        firstChunk = false;
                        body = chunk;
                    } else {
                        body = Buffer.concat([body, chunk]);
                    }
                });
                req.on('end', () => {

                    if (req.headers.hasOwnProperty('twitch-eventsub-message-signature')) {
                        let id = req.headers['twitch-eventsub-message-id'];
                        let timestamp = req.headers['twitch-eventsub-message-timestamp'];
                        let sigParts = req.headers['twitch-eventsub-message-signature'].split('=');

                        let computedSig = crypto.createHmac('sha256', config.secret)
                            .update(id + timestamp + body)
                            .digest('hex');
                        let sentSig = sigParts[1];

                        if (computedSig !== sentSig) {
                            console.log("SIGNATURE MISMATCH:");
                            console.log("Expected: ", computedSig);
                            console.log("Got ", sentSig);
                            res.writeHead(401, "Invalid Signature");
                            res.end();
                        } else {
                            console.log("GOOD SIGNATURE");
                            let parsedBody = JSON.parse(body.toString());
                            console.log(JSON.stringify(parsedBody));
                            switch (req.headers['twitch-eventsub-message-type']) {
                                case "webhook_callback_verification": {
                                    res.writeHead(200, "OK");
                                    res.end(parsedBody.challenge);
                                    console.log("Acknowledged new subscription with id", parsedBody.subscription.id);
                                    break;
                                }
                                case "notification": {
                                    res.writeHead(204, "No Content");
                                    res.end();
                                    console.log("Got a notification!");
                                    switch (parsedBody.subscription.type) {
                                        case "channel.follow": {
                                            console.log(parsedBody.event.user_name, "has followed", parsedBody.event.broadcaster_user_name, "!");

                                            for (const [, conn] of Object.entries(authenticatedConnections)) {
                                                conn.send(JSON.stringify(parsedBody.event));
                                            }

                                            break;
                                        }
                                        default: {
                                            console.log("Got unknown notification type", parsedBody.subscription.type);
                                        }
                                    }
                                    break;
                                }
                                case "revocation": {
                                    res.writeHead(204, "No Content");
                                    res.end();
                                    console.log("Revocation of subsctiption", parsedBody.subscription.id, "acknowledged.");
                                    break;
                                }
                            }

                        }
                    }
                });

            } else {
                res.writeHead(405, "Method not allowed");
                res.end("What are you doing?");
            }
            break;
        }
        case "login": {
            console.log("login");
            // TODO: Actually log in and handle oauth
            res.writeHead(200, "OK");
            res.end("We will log you in here.");
            break;
        }
        default: {
            console.log("Unknown path " + req.url);
            res.writeHead(404, "Not Found");
            res.end("Not Found");
        }
    }
});
console.log("port: ", config.port);

let wsServer = https.createServer({
    cert: fs.readFileSync(config.websocket_cert_path),
    key: fs.readFileSync(config.websocket_key_path)
});
const wss = new ws.Server({ server: wsServer});

wss.on('connection', function connection(ws) {
    let authenticated = false;
    let myID = -1;
    ws.on('message', function incoming(message) {
        let parsed = {};
        try {
            parsed = JSON.parse(message);
        } catch (e) {
            ws.close();
            console.error("Error parsing message as json. Disconnecting.");
            return
        }
        if (!authenticated) {
            authenticated = parsed.password === config.websocket_secret;
            if (!authenticated) {
                ws.send(JSON.stringify({success: false, error:"WRONG_PASSWORD"}));
            } else {
                ws.send(JSON.stringify({success: true}));
                myID = ++id_counter;
                authenticatedConnections[myID] = ws;
            }
        } else {
            // Listen to potential commands here, but nothing is implemented here as we only ever expect one client and broadcaster to listen to, anyway.
            ws.send(JSON.stringify({success: true, message: "You are authenticated, but we don't support you doing anything yet, so I'm ignoring you."}));
        }
    });

    ws.on('close', function () {
        if (authenticated) {
            delete authenticatedConnections[myID];
        }
    })
});

Promise.all([server.listen(config.port), wsServer.listen(config.websocket_port)]).then(() => console.log("Boot command sent."));
