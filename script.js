/**
 * Frida hook script v3 - captures raw POST data + sprintf construction
 */
var libName = "libAkAudioVisiual.so";
var base = null;

function waitForLib(name, cb) {
    var found = false;
    var check = function () {
        var m = Process.findModuleByName(name);
        if (m && !found) { found = true; console.log("[+] " + name + " at " + m.base); cb(m.base); }
    };
    check(); var interval = setInterval(function () { if (found) clearInterval(interval); else check(); }, 100);
}

function hexdump_safe(ptr, len) {
    try { return hexdump(ptr, { offset: 0, length: Math.min(len, 4096), header: true, ansi: false }); }
    catch (e) { return "(err)"; }
}
function tryReadCString(ptr) {
    try { if (ptr.isNull()) return "(null)"; var s = ptr.readCString(); return s || "(empty)"; }
    catch (e) { return "(err)"; }
}

var OFFSETS = {
    curl_setopt_wrapper:    0xedff0,
    CURLOPT_URL:            0x2712,
    CURLOPT_POSTFIELDS:     0x271f,
    CURLOPT_COPYPOSTFIELDS: 0x27b5,
    SSL_read:               0x135c40,
    SSL_write:              0x135f64,
    DES_ecb_encrypt:        0x17d3c4,
    DES_set_key_unchecked:  0x17d700,
};

waitForLib(libName, function (baseAddr) {
    base = baseAddr;
    console.log("[+] Base: " + base + "\n");

    // Dump strings
    console.log("=== STRINGS ===");
    console.log("https = " + tryReadCString(base.add(0x2ae853)));
    console.log("sad   = " + tryReadCString(base.add(0x2ae859)));
    console.log("sad1  = " + tryReadCString(base.add(0x2ae85d)));
    console.log("sad2  = " + tryReadCString(base.add(0x2ae862)));
    try {
        var k = ""; for (var i = 0; i < 20; i++) {
            var c = base.add(0x2ae831 + i*2).readU16();
            if (c === 0) break; k += String.fromCharCode(c);
        }
        console.log("key   = " + k);
    } catch(e) {}
    console.log("pkg   = " + tryReadCString(base.add(0x2ae7c3)));
    console.log("===============\n");

    // ---- 1. CURL SETOPT ----
    var setopt = base.add(OFFSETS.curl_setopt_wrapper);
    Interceptor.attach(setopt, {
        onEnter: function (args) {
            var opt = args[1].toInt32();
            var val = args[2];
            if (opt === OFFSETS.CURLOPT_URL) {
                console.log("\n=== [CURLOPT_URL] " + tryReadCString(val));
            }
            else if (opt === OFFSETS.CURLOPT_POSTFIELDS || opt === OFFSETS.CURLOPT_COPYPOSTFIELDS) {
                console.log("\n=== [CURLOPT_POSTFIELDS] ===");
                console.log(tryReadCString(val));
                console.log(hexdump_safe(val, 512));
                console.log("=== end POST data ===\n");
            }
            else if (opt === 0x2710) { // CURLOPT_HTTPHEADER
                console.log("[HTTPHEADER]");
                try {
                    var node = val, i = 0;
                    while (!node.isNull() && i < 20) {
                        var d = node.readPointer();
                        if (!d.isNull()) console.log("  " + tryReadCString(d));
                        node = node.add(Process.pointerSize); i++;
                    }
                } catch(e) {}
            }
        },
    });

    // ---- 2. SSL_write - outbound request ----
    var sslW = base.add(OFFSETS.SSL_write);
    Interceptor.attach(sslW, {
        onEnter: function (args) { this.buf = args[1]; this.len = args[2].toInt32(); },
        onLeave: function (retval) {
            var n = retval.toInt32();
            if (n > 0 && n < 65536) {
                console.log("\n[SSL_write] " + n + " bytes");
                console.log(hexdump_safe(this.buf, n));
                try { console.log("[TEXT]\n" + this.buf.readUtf8String(Math.min(n, 4096))); } catch(e) {}
            }
        },
    });

    // ---- 3. SSL_read - inbound response ----
    var sslR = base.add(OFFSETS.SSL_read);
    Interceptor.attach(sslR, {
        onEnter: function (args) { this.buf = args[1]; this.len = args[2].toInt32(); },
        onLeave: function (retval) {
            var n = retval.toInt32();
            if (n > 0 && n < 65536) {
                console.log("\n[SSL_read] " + n + " bytes");
                console.log(hexdump_safe(this.buf, n));
                try { console.log("[TEXT]\n" + this.buf.readUtf8String(Math.min(n, 4096))); } catch(e) {}
            }
        },
    });

    // ---- 4. DES ----
    var desKeys = {}, desCount = 0;
    var desEnc = base.add(OFFSETS.DES_ecb_encrypt);
    Interceptor.attach(desEnc, {
        onEnter: function (args) {
            this.input = args[0]; this.output = args[1];
            this.sched = args[2]; this.enc = args[3].toInt32();
        },
        onLeave: function (retval) {
            desCount++;
            var dir = this.enc === 1 ? "ENC" : "DEC";
            console.log("[DES_ecb #" + desCount + "] " + dir + " key=" + (desKeys[retval.toString()] || "?"));
            var ptr = this.enc === 0 ? this.output : this.input;
            console.log(hexdump_safe(ptr, 8));
            try { console.log("[TXT] " + ptr.readCString(8)); } catch(e) {}
        },
    });
    var desKey = base.add(OFFSETS.DES_set_key_unchecked);
    Interceptor.attach(desKey, {
        onEnter: function (args) { this.kptr = args[0]; },
        onLeave: function (retval) {
            try {
                var b = this.kptr.readByteArray(8);
                var h = Array.from(new Uint8Array(b)).map(x => ("0"+x.toString(16)).slice(-2)).join("");
                desKeys[retval.toString()] = h;
                console.log("[DES_KEY] " + h);
            } catch(e) {}
        },
    });

    // ---- 5. sprintf: catch "data=" format string ----
    var snprintf = Module.findExportByName(null, "snprintf");
    var sprintf_ = Module.findExportByName(null, "sprintf");
    [snprintf, sprintf_].forEach(function (addr) {
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.outbuf = args[0];
                this.fmt = tryReadCString(args[1] || args[0]); // args[0] for sprintf, args[2] for snprintf
            },
            onLeave: function (retval) {
                if (this.fmt && this.fmt.indexOf("data") !== -1) {
                    console.log("\n[sprintf fmt=" + this.fmt + "] result=" + tryReadCString(this.outbuf));
                }
            },
        });
    });

    console.log("[+] Hooks active.\n");
});
