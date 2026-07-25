/**
 * Frida hook script for libAkAudioVisiual.so
 * Logs: server URL (plaintext), request/response data (decrypted), DES operations
 * 
 * Usage: frida -U -l hook_log.js <package_name>
 *    or:  frida -U -f <package_name> -l hook_log.js --no-pause
 */

var libName = "libAkAudioVisiual.so";
var base = null;

// Wait for the library to load
function waitForLib(name, cb) {
    var found = false;
    var check = function () {
        var m = Process.findModuleByName(name);
        if (m && !found) {
            found = true;
            console.log("[+] " + name + " loaded at " + m.base);
            cb(m.base);
        }
    };
    // Check immediately
    check();
    // Also poll
    var interval = setInterval(function () {
        if (found) {
            clearInterval(interval);
            return;
        }
        check();
    }, 100);
}

// =========================================================
// OFFSETS (add base address at runtime)
// =========================================================
var OFFSETS = {
    // curl / URL
    curl_easy_setopt_wrapper: 0xedff0,
    CURLOPT_URL: 0x27fe, // 10238

    // SSL (plaintext request/response)
    SSL_read:  0x135c40,
    SSL_write: 0x135f64,
    SSL_connect: 0x138b8c,

    // DES decryption
    DES_set_key_unchecked: 0x17d700,
    DES_ecb_encrypt: 0x17d3c4,

    // Strings in .rodata
    str_https: 0x2ae853,
    str_key:   0x2ae831,
};

// =========================================================
// Helpers
// =========================================================
var MAX_DUMP = 4096;

function hexdump_safe(ptr, len) {
    try {
        var n = Math.min(len, MAX_DUMP);
        return hexdump(ptr, { offset: 0, length: n, header: true, ansi: true });
    } catch (e) {
        return "(read error: " + e + ")";
    }
}

function tryReadCString(ptr) {
    try {
        if (ptr.isNull()) return "(null)";
        var s = ptr.readCString();
        return s ? s : "(empty)";
    } catch (e) {
        return "(error: " + e + ")";
    }
}

// Track DES keys
var desKeys = {};
var sslConnections = {};

// =========================================================
// HOOKS
// =========================================================
waitForLib(libName, function (baseAddr) {
    base = baseAddr;
    console.log("[+] Base address: " + base);

    // --- 1. curl_easy_setopt wrapper -> log CURLOPT_URL ---
    var setoptAddr = base.add(OFFSETS.curl_easy_setopt_wrapper);
    console.log("[*] Hooking curl_easy_setopt wrapper at " + setoptAddr);

    Interceptor.attach(setoptAddr, {
        onEnter: function (args) {
            this.option = args[1].toInt32();
            this.value = args[2];

            if (this.option === OFFSETS.CURLOPT_URL) {
                console.log("\n[CURLOPT_URL] " + tryReadCString(this.value));
            } else if (this.option === 0x2711) { // CURLOPT_WRITEDATA
                // could log but noisy
            } else if (this.option === 0x4e2b) { // CURLOPT_WRITEFUNCTION
                console.log("[CURLOPT_WRITEFUNCTION] callback = " + this.value);
            }
        },
    });

    // --- 2. SSL_read -> log decrypted server response ---
    var sslReadAddr = base.add(OFFSETS.SSL_read);
    console.log("[*] Hooking SSL_read at " + sslReadAddr);

    Interceptor.attach(sslReadAddr, {
        onEnter: function (args) {
            this.ssl = args[0];
            this.buf = args[1];
            this.len = args[2].toInt32();
        },
        onLeave: function (retval) {
            var n = retval.toInt32();
            if (n > 0 && n < 65536) {
                console.log("\n[SSL_read]  len=" + this.len + " returned=" + n);
                console.log(hexdump_safe(this.buf, n));
                // Try as text
                try {
                    var txt = this.buf.readUtf8String(Math.min(n, 2000));
                    if (txt && txt.length > 1) {
                        console.log("[SSL_read TEXT]\n" + txt.substring(0, 1000));
                    }
                } catch (e) { }
            } else if (n < 0) {
                console.log("[SSL_read]  ERROR code=" + n);
            }
        },
    });

    // --- 3. SSL_write -> log decrypted request ---
    var sslWriteAddr = base.add(OFFSETS.SSL_write);
    console.log("[*] Hooking SSL_write at " + sslWriteAddr);

    Interceptor.attach(sslWriteAddr, {
        onEnter: function (args) {
            this.ssl = args[0];
            this.buf = args[1];
            this.len = args[2].toInt32();
        },
        onLeave: function (retval) {
            var n = retval.toInt32();
            if (n > 0 && n < 65536) {
                console.log("\n[SSL_write] len=" + this.len + " sent=" + n);
                console.log(hexdump_safe(this.buf, n));
                // Try as text
                try {
                    var txt = this.buf.readUtf8String(Math.min(n, 2000));
                    if (txt && txt.length > 1) {
                        console.log("[SSL_write TEXT]\n" + txt.substring(0, 1000));
                    }
                } catch (e) { }
            }
        },
    });

    // --- 4. SSL_connect -> log when TLS handshake starts ---
    var sslConnectAddr = base.add(OFFSETS.SSL_connect);
    console.log("[*] Hooking SSL_connect at " + sslConnectAddr);

    Interceptor.attach(sslConnectAddr, {
        onEnter: function (args) {
            console.log("\n[SSL_connect] starting TLS handshake, ssl=" + args[0]);
        },
        onLeave: function (retval) {
            console.log("[SSL_connect] result=" + retval);
        },
    });

    // --- 5. DES_set_key -> log encryption keys ---
    var desSetKeyAddr = base.add(OFFSETS.DES_set_key_unchecked);
    console.log("[*] Hooking DES_set_key_unchecked at " + desSetKeyAddr);

    Interceptor.attach(desSetKeyAddr, {
        onEnter: function (args) {
            this.key = args[0];
            this.sched = args[1];
        },
        onLeave: function (retval) {
            try {
                var keyBytes = this.key.readByteArray(8);
                var keyHex = "";
                var keyArr = new Uint8Array(keyBytes);
                for (var i = 0; i < 8; i++) {
                    keyHex += ("0" + keyArr[i].toString(16)).slice(-2);
                }
                console.log("[DES_set_key] key=" + keyHex + " schedule=" + this.sched);
                desKeys[this.sched.toString()] = keyHex;
            } catch (e) { }
        },
    });

    // --- 6. DES_ecb_encrypt -> log encrypted/decrypted blocks ---
    var desEncAddr = base.add(OFFSETS.DES_ecb_encrypt);
    console.log("[*] Hooking DES_ecb_encrypt at " + desEncAddr);

    var desCount = 0;
    Interceptor.attach(desEncAddr, {
        onEnter: function (args) {
            this.input = args[0];
            this.output = args[1];
            this.sched = args[2];
            this.enc = args[3].toInt32(); // 0=decrypt, 1=encrypt
        },
        onLeave: function (retval) {
            desCount++;
            var dir = this.enc === 1 ? "ENCRYPT" : "DECRYPT";
            var keyHint = desKeys[this.sched.toString()] || "unknown";
            console.log("\n[DES_ecb_encrypt #" + desCount + "] " + dir + "  key=" + keyHint);

            if (this.enc === 0) {
                // Decrypt: show output (plaintext)
                console.log("[DES_decrypt OUTPUT (plaintext):]");
                console.log(hexdump_safe(this.output, 8));
                try {
                    var txt = this.output.readUtf8String(8);
                    console.log("[DES_decrypt TEXT]: " + txt);
                } catch (e) { }
            } else {
                // Encrypt: show input (plaintext before encryption)
                console.log("[DES_encrypt INPUT (plaintext):]");
                console.log(hexdump_safe(this.input, 8));
                try {
                    var txt = this.input.readUtf8String(8);
                    console.log("[DES_encrypt TEXT]: " + txt);
                } catch (e) { }
            }
        },
    });

    // --- 7. Dump the .rodata strings ---
    console.log("\n[*] Dumping key strings from .rodata:");
    console.log("    https  = " + tryReadCString(base.add(OFFSETS.str_https)));
    console.log("    sad    = " + tryReadCString(base.add(OFFSETS.str_https + 6)));
    console.log("    sad1   = " + tryReadCString(base.add(OFFSETS.str_https + 10)));
    console.log("    sad2   = " + tryReadCString(base.add(OFFSETS.str_https + 15)));
    console.log("    key    = " + tryReadCString(base.add(OFFSETS.str_key)));
    console.log("    cmdline= " + tryReadCString(base.add(0x2ae7b0)));
    console.log("[+] All hooks ready. Waiting for activity...\n");
});
