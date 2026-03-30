// bypass_v5.js - B站 Frida 绕过（盲化策略）
// 策略：让安全线程正常运行，但屏蔽所有 Frida 特征
// !! 单独使用，不配合 bypass.js !!

function findExport(modName, symName) {
    var mod = Process.findModuleByName(modName);
    if (!mod) return null;
    var addr = null;
    mod.enumerateExports().forEach(function(e) {
        if (e.name === symName) addr = e.address;
    });
    return addr;
}

// ── Part 1: strstr 过滤 Frida 特征串 ─────────────────────────
var HIDE = ["frida", "gum-js-loop", "linjector", "frida-agent"];
var strstrAddr = findExport("libc.so", "strstr");
if (strstrAddr) {
    Interceptor.attach(strstrAddr, {
        onEnter: function(args) {
            this.block = false;
            try {
                var needle = args[1].readCString();
                if (needle) {
                    var low = needle.toLowerCase();
                    for (var i = 0; i < HIDE.length; i++) {
                        if (low.indexOf(HIDE[i]) !== -1) { this.block = true; break; }
                    }
                }
            } catch(e) {}
        },
        onLeave: function(retval) {
            if (this.block) retval.replace(ptr(0));
        }
    });
    console.log("[+] Part1: strstr hooked");
} else { console.log("[-] strstr not found"); }

// ── Part 2: connect 屏蔽 frida-server 端口 ───────────────────
var connectAddr = findExport("libc.so", "connect");
if (connectAddr) {
    Interceptor.attach(connectAddr, {
        onEnter: function(args) {
            this.block = false;
            try {
                var sa = args[1];
                if (sa.readU16() === 2) {
                    var port = ((sa.add(2).readU8() << 8) | sa.add(3).readU8());
                    if (port === 27042 || port === 27043) {
                        this.block = true;
                        console.log("[bypass] blocked connect to port " + port);
                    }
                }
            } catch(e) {}
        },
        onLeave: function(retval) {
            if (this.block) retval.replace(ptr(-1));
        }
    });
    console.log("[+] Part2: connect hooked");
} else { console.log("[-] connect not found"); }

// ── Part 3: /proc/self/maps 过滤 Frida 相关行 ────────────────
var mapsOpenFds = {};

var openAddr = findExport("libc.so", "open");
if (!openAddr) openAddr = findExport("libc.so", "__open_2");
if (openAddr) {
    Interceptor.attach(openAddr, {
        onEnter: function(args) {
            try {
                var path = args[0].readCString();
                this.isMaps = (path && path.indexOf("/proc/") !== -1 && path.indexOf("maps") !== -1);
            } catch(e) { this.isMaps = false; }
        },
        onLeave: function(retval) {
            if (this.isMaps) {
                var fd = retval.toInt32();
                if (fd >= 0) { mapsOpenFds[fd] = true; console.log("[bypass] /proc/*/maps opened fd=" + fd); }
            }
        }
    });
    console.log("[+] Part3: open hooked for maps");
}

var readAddr = findExport("libc.so", "read");
if (readAddr) {
    Interceptor.attach(readAddr, {
        onEnter: function(args) {
            this.fd = args[0].toInt32();
            this.buf = args[1];
            this.tracked = !!mapsOpenFds[this.fd];
        },
        onLeave: function(retval) {
            if (!this.tracked) return;
            var len = retval.toInt32();
            if (len <= 0) return;
            try {
                var bytes = new Uint8Array(this.buf.readByteArray(len));
                var str = "";
                for (var i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
                var lines = str.split('\n');
                var filtered = lines.filter(function(line) {
                    return line.indexOf('frida') === -1 && line.indexOf('gum-js') === -1;
                });
                var newStr = filtered.join('\n');
                this.buf.writeUtf8String(newStr);
                retval.replace(ptr(newStr.length));
            } catch(e) {}
        }
    });
    console.log("[+] Part3: read hooked for maps filtering");
}

var closeAddr = findExport("libc.so", "close");
if (closeAddr) {
    Interceptor.attach(closeAddr, {
        onEnter: function(args) { delete mapsOpenFds[args[0].toInt32()]; }
    });
}

console.log("[*] bypass_v5 ready — 安全线程自由运行，Frida 特征已隐藏");
