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

let server = http.createServer(async (req, res) => {
    const calledURL = new URL(req.url, 'https://' + (req.headers.hasOwnProperty('x-forwarded-host') ? req.headers['x-forwarded-host'] : req.headers['host']));
    switch (calledURL.pathname.substring(1)) {
        case "twitch/callback": {
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
            let code = calledURL.searchParams.get('code');
            if (code) {
                let response;
                try {
                    response = await got({
                        url: 'https://id.twitch.tv/oauth2/token',
                        searchParams: {
                            client_id: config.client_id,
                            client_secret: config.client_secret,
                            code: code,
                            grant_type: 'authorization_code',
                            redirect_uri: 'https://' + calledURL.host + calledURL.pathname
                        },
                        method: 'POST'
                    }).json();
                } catch (e) {
                    console.error(e);
                    try {
                        console.error(e.response.body);
                    } catch (e) {}
                    res.writeHead(500, "Error");
                    res.end("Something didn't work here - most likely, the code was invalid.");
                    return;
                }
                let token = response.access_token;
                let verifyResponse;
                try {
                    verifyResponse = await got({
                        url: 'https://id.twitch.tv/oauth2/validate',
                        headers: {
                            Authorization: 'OAuth ' + token
                        },
                        method: 'GET'
                    }).json();
                } catch (e) {
                    console.error(e);
                    try {
                        console.error(e.response.body);
                    } catch (e) {}
                    res.writeHead(500, "Error");
                    res.end("Something didn't work here - most likely, the code was invalid.");
                    return;
                }
                if (verifyResponse.user_id !== config.expected_user_id) {
                    res.writeHead(401, "Unauthorized");
                    res.end("You tried to authorize a user i did not expect. Please go away.");
                    console.log(verifyResponse.login, "gave us a token? thanks?", JSON.stringify(verifyResponse))
                } else {
                    res.writeHead(200, "OK");
                    res.end("Thank you for verifying yourself!");
                    console.log("Verified user", verifyResponse.login);
                }
            } else {
                res.writeHead(302, "Found", {'Location':'https://id.twitch.tv/oauth2/authorize' +
                        '?client_id=' + config.client_id +
                '&redirect_uri=' + encodeURIComponent(calledURL.toString()) +
                '&response_type=code'});
                res.end("You should've been redirected.");
            }

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
