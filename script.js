/**
 * Frida hook script for libAkAudioVisiual.so v2
 * Fixes: CURLOPT_URL=0x2712, wide-char key, captures all curl opts
 */

var libName = "libAkAudioVisiual.so";
var base = null;

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
    check();
    var interval = setInterval(function () {
        if (found) { clearInterval(interval); return; }
        check();
    }, 100);
}

var OFFSETS = {
    curl_setopt_wrapper: 0xedff0,
    CURLOPT_URL:         0x2712,
    CURLOPT_WRITEDATA:   0x2711,
    CURLOPT_WRITEFUNCTION: 0x4e2b,
    SSL_read:             0x135c40,
    SSL_write:            0x135f64,
    SSL_connect:          0x138b8c,
    DES_ecb_encrypt:      0x17d3c4,
    DES_set_key_unchecked: 0x17d700,
};

function hexdump_safe(ptr, len) {
    try {
        return hexdump(ptr, { offset: 0, length: Math.min(len, 4096), header: true, ansi: false });
    } catch (e) { return "(err)"; }
}

function tryReadCString(ptr) {
    try { if (ptr.isNull()) return "(null)"; var s = ptr.readCString(); return s || "(empty)"; }
    catch (e) { return "(err)"; }
}

function tryReadWideString(ptr, maxlen) {
    // Read wide-char (UTF-16) string: char, 0x00, char, 0x00, ...
    try {
        var out = "";
        for (var i = 0; i < (maxlen || 64); i++) {
            var b0 = ptr.add(i * 2).readU8();
            var b1 = ptr.add(i * 2 + 1).readU8();
            if (b0 === 0 && b1 === 0) break;
            if (b1 === 0) out += String.fromCharCode(b0);
            else out += "?";
        }
        return out || "(empty)";
    } catch (e) { return "(err)"; }
}

var desKeys = {};
var curlOptions = {};

// ----- Known CURLOPT names -----
var CURLOPT_NAMES = {
    0x2712: "URL",
    0x2711: "WRITEDATA",
    0x4e2b: "WRITEFUNCTION",
    0x002b: "VERBOSE",
    0x0040: "SSL_VERIFYPEER",
    0x0051: "SSL_VERIFYHOST",
    0x2713: "PROXY",
    0x002d: "FOLLOWLOCATION",
    0x0e28: "POSTFIELDS",
    0x2714: "CUSTOMREQUEST",
    0x2710: "HTTPHEADER",
    0x00c9: "TIMEOUT",
};

waitForLib(libName, function (baseAddr) {
    base = baseAddr;
    console.log("[+] Base: " + base + "\n");

    // --- 1. Curl setopt: log ALL options ---
    var setopt = base.add(OFFSETS.curl_setopt_wrapper);
    Interceptor.attach(setopt, {
        onEnter: function (args) {
            var opt = args[1].toInt32();
            var val = args[2];
            var name = CURLOPT_NAMES[opt] || ("0x" + opt.toString(16));

            if (opt === OFFSETS.CURLOPT_URL) {
                console.log("========================================");
                console.log("[CURLOPT_URL] " + tryReadCString(val));
                console.log("========================================");
            } else if (opt === OFFSETS.CURLOPT_CUSTOMREQUEST || 
                       opt === OFFSETS.CURLOPT_POSTFIELDS) {
                console.log("[CURLOPT_" + name + "] " + tryReadCString(val));
            } else if (opt === OFFSETS.CURLOPT_HTTPHEADER) {
                console.log("[CURLOPT_HTTPHEADER] ptr=" + val);
                // chain through the curl_slist
                try {
                    var node = val;
                    var i = 0;
                    while (!node.isNull() && i < 20) {
                        var data = node.readPointer();
                        if (!data.isNull()) {
                            console.log("  header[" + i + "]: " + tryReadCString(data));
                        }
                        node = node.add(Process.pointerSize);
                        i++;
                    }
                } catch (e) { }
            } else if (opt === OFFSETS.CURLOPT_WRITEFUNCTION) {
                console.log("[CURLOPT_WRITEFUNCTION] cb=" + val + " name=" + DebugSymbol.fromAddress(val));
            } else if (opt === OFFSETS.CURLOPT_WRITEDATA) {
                console.log("[CURLOPT_WRITEDATA] ptr=" + val);
            } else if (opt === OFFSETS.CURLOPT_SSL_VERIFYPEER || 
                       opt === OFFSETS.CURLOPT_SSL_VERIFYHOST) {
                console.log("[CURLOPT_" + name + "] " + val);
            } 
        },
    });

    // --- 2. SSL_read: decrypted server response ---
    var sslRead = base.add(OFFSETS.SSL_read);
    Interceptor.attach(sslRead, {
        onEnter: function (args) {
            this.buf = args[1];
            this.len = args[2].toInt32();
        },
        onLeave: function (retval) {
            var n = retval.toInt32();
            if (n > 0 && n < 65536) {
                console.log("\n[SSL_read] " + n + " bytes (response)");
                console.log(hexdump_safe(this.buf, n));
                try {
                    var txt = this.buf.readUtf8String(Math.min(n, 3000));
                    console.log("[TEXT]\n" + txt.substring(0, 2000));
                } catch (e) { }
                console.log("");
            }
        },
    });

    // --- 3. SSL_write: decrypted request ---
    var sslWrite = base.add(OFFSETS.SSL_write);
    Interceptor.attach(sslWrite, {
        onEnter: function (args) {
            this.buf = args[1];
            this.len = args[2].toInt32();
        },
        onLeave: function (retval) {
            var n = retval.toInt32();
            if (n > 0 && n < 65536) {
                console.log("\n[SSL_write] " + n + " bytes (request)");
                console.log(hexdump_safe(this.buf, n));
                try {
                    var txt = this.buf.readUtf8String(Math.min(n, 3000));
                    console.log("[TEXT]\n" + txt.substring(0, 2000));
                } catch (e) { }
                console.log("");
            }
        },
    });

    // --- 4. SSL_connect ---
    var sslConn = base.add(OFFSETS.SSL_connect);
    Interceptor.attach(sslConn, {
        onEnter: function (args) {
            console.log("\n[SSL_connect] establishing TLS...");
        },
    });

    // --- 5. DES decrypt ---
    var desEnc = base.add(OFFSETS.DES_ecb_encrypt);
    var desCount = 0;
    Interceptor.attach(desEnc, {
        onEnter: function (args) {
            this.input = args[0];
            this.output = args[1];
            this.sched = args[2];
            this.enc = args[3].toInt32();
        },
        onLeave: function (retval) {
            desCount++;
            var dir = this.enc === 1 ? "ENC" : "DEC";
            var keyHint = desKeys[this.sched.toString()] || "?";
            console.log("[DES_ecb #" + desCount + "] " + dir + " key=" + keyHint);
            if (this.enc === 0) {
                console.log(hexdump_safe(this.output, 8));
                try { console.log("[TXT] " + this.output.readCString(8)); } catch(e) {}
            } else {
                console.log(hexdump_safe(this.input, 8));
                try { console.log("[TXT] " + this.input.readCString(8)); } catch(e) {}
            }
            console.log("");
        },
    });

    // --- 6. DES keys ---
    var desKey = base.add(OFFSETS.DES_set_key_unchecked);
    Interceptor.attach(desKey, {
        onEnter: function (args) { this.kptr = args[0]; },
        onLeave: function (retval) {
            try {
                var kb = this.kptr.readByteArray(8);
                var kh = Array.from(new Uint8Array(kb)).map(b => ("0"+b.toString(16)).slice(-2)).join("");
                console.log("[DES_KEY] " + kh);
            } catch(e) {}
        },
    });

    // --- Dump strings ---
    console.log("=== .rodata strings ===");
    console.log("https   = " + tryReadCString(base.add(0x2ae853)));
    console.log("sad     = " + tryReadCString(base.add(0x2ae859)));
    console.log("sad1    = " + tryReadCString(base.add(0x2ae85d)));
    console.log("sad2    = " + tryReadCString(base.add(0x2ae862)));
    console.log("key (wide) = " + tryReadWideString(base.add(0x2ae831), 20));
    console.log("pkg     = " + tryReadCString(base.add(0x2ae7c3)));
    console.log("Mod msg = " + tryReadCString(base.add(0x2ae881)).substring(0, 60));
    console.log("========================\n");
    console.log("[+] All hooks active.\n");
});
