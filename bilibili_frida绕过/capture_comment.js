// capture_comment.js v2 - 抓取 B站评论接口完整请求（头+体+响应）
// 修复：实现 HPACK Huffman 解码，能正确显示请求头
// 用法: frida -U -f tv.danmaku.bili -l bypass.js -l capture_comment.js

var sslHostMap = {};

// ── HPACK Huffman 解码表 (RFC 7541 Appendix B) ─────────────────
// 每个符号的 [code, bitLength]，共 257 个（0-255 + EOS=256）
var _HCODES = [
    0x1ff8,0x7fffd8,0xfffffe2,0xfffffe3,0xfffffe4,0xfffffe5,0xfffffe6,0xfffffe7,
    0xfffffe8,0xffffea,0x3ffffffc,0xfffffe9,0xfffffea,0x3ffffffd,0xfffffeb,0xfffffec,
    0xfffffed,0xfffffee,0xfffffef,0xffffff0,0xffffff1,0xffffff2,0x3ffffffe,0xffffff3,
    0xffffff4,0xffffff5,0xffffff6,0xffffff7,0xffffff8,0xffffff9,0xffffffa,0xffffffb,
    0x14,0x3f8,0x3f9,0xffa,0x1ff9,0x15,0xf8,0x7fa,
    0x3fa,0x3fb,0xf9,0x7fb,0xfa,0x16,0x17,0x18,
    0x0,0x1,0x2,0x19,0x1a,0x1b,0x1c,0x1d,
    0x1e,0x1f,0x5c,0xfb,0x7ffc,0x20,0xffb,0x3fc,
    0x1ffa,0x21,0x5d,0x5e,0x5f,0x60,0x61,0x62,
    0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,
    0x6b,0x6c,0x6d,0x6e,0x6f,0x70,0x71,0x72,
    0xfc,0x73,0xfd,0x1ffb,0x7fff0,0x1ffc,0x3ffc,0x22,
    0x7ffd,0x3,0x23,0x4,0x24,0x5,0x25,0x26,
    0x27,0x6,0x74,0x75,0x28,0x29,0x2a,0x7,
    0x2b,0x76,0x2c,0x8,0x9,0x2d,0x77,0x78,
    0x79,0x7a,0x7b,0x7ffe,0x7fc,0x3ffd,0x1ffd,0xffffffc,
    0xfffe6,0x3fffd2,0xfffe7,0xfffe8,0x3fffd3,0x3fffd4,0x3fffd5,0x7fffd9,
    0x3fffd6,0x7fffda,0x7fffdb,0x7fffdc,0x7fffdd,0x7fffde,0xffffeb,0x7fffdf,
    0xffffec,0xffffed,0x3fffd7,0x7fffe0,0xffffee,0x7fffe1,0x7fffe2,0x7fffe3,
    0x7fffe4,0x1fffdc,0x3fffd8,0x7fffe5,0x3fffd9,0x7fffe6,0x7fffe7,0xffffef,
    0x3fffda,0x1fffdd,0xfffe9,0x3fffdb,0x3fffdc,0x7fffe8,0x7fffe9,0x1fffde,
    0x7fffea,0x3fffdd,0x3fffde,0xfffff0,0x1fffdf,0x3fffdf,0x7fffeb,0x7fffec,
    0x1fffe0,0x1fffe1,0x3fffe0,0x1fffe2,0x7fffed,0x3fffe1,0x7fffee,0x7fffef,
    0xfffea,0x3fffe2,0x3fffe3,0x3fffe4,0x7ffff0,0x3fffe5,0x3fffe6,0x7ffff1,
    0x3ffffe0,0x3ffffe1,0xfffeb,0x7fff1,0x3fffe7,0x7ffff2,0x3fffe8,0x1ffffec,
    0x3ffffe2,0x3ffffe3,0x3ffffe4,0x7ffffde,0x7ffffdf,0x3ffffe5,0xfffff1,0x1ffffed,
    0x7fff2,0x1fffe3,0x3ffffe6,0x7ffffe0,0x7ffffe1,0x3ffffe7,0x7ffffe2,0xfffff2,
    0x1fffe4,0x1fffe5,0x3ffffe8,0x3ffffe9,0xffffffd,0x7ffffe3,0x7ffffe4,0x7ffffe5,
    0xfffec,0xfffff3,0xfffed,0x1fffe6,0x3fffe9,0x1fffe7,0x1fffe8,0x7ffff3,
    0x3fffea,0x3fffeb,0x1ffffee,0x1ffffef,0xfffff4,0xfffff5,0x3ffffea,0x7ffff4,
    0x3ffffeb,0x7ffffe6,0x3ffffec,0x3ffffed,0x7ffffe7,0x7ffffe8,0x7ffffe9,0x7ffffea,
    0x7ffffeb,0xffffffe,0x7ffffec,0x7ffffed,0x7ffffee,0x7ffffef,0x7fffff0,0x3ffffee,
    0x3fffffff
];
var _HBITS = [
    13,23,28,28,28,28,28,28,28,24,30,28,28,30,28,28,
    28,28,28,28,28,28,30,28,28,28,28,28,28,28,28,28,
    6,10,10,12,13,6,8,11,10,10,8,11,8,6,6,6,
    5,5,5,6,6,6,6,6,6,6,7,8,15,6,12,10,
    13,6,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,8,7,8,13,19,13,14,6,
    15,5,6,5,6,5,6,6,6,5,7,7,6,6,6,5,
    6,7,6,5,5,6,7,7,7,7,7,15,11,14,13,28,
    20,22,20,20,22,22,22,23,22,23,23,23,23,23,24,23,
    24,24,22,23,24,23,23,23,23,21,22,23,22,23,23,24,
    22,21,20,22,22,23,23,21,23,22,22,24,21,22,23,23,
    21,21,22,21,23,22,23,23,20,22,22,22,23,22,22,23,
    26,26,20,19,22,23,22,25,26,26,26,27,27,26,24,25,
    19,21,26,27,27,26,27,24,21,21,26,26,28,27,27,27,
    20,24,20,21,22,21,21,23,22,22,25,25,24,24,26,23,
    26,27,26,26,27,27,27,27,27,28,27,27,27,27,27,26,
    30
];

// 构建 Huffman 解码树（启动时执行一次）
var _huffRoot = [null, null]; // [0-child, 1-child], leaf = number (symbol)
(function buildHuffTree() {
    for (var sym = 0; sym <= 256; sym++) {
        var code = _HCODES[sym], bits = _HBITS[sym];
        var node = _huffRoot;
        for (var i = bits - 1; i >= 0; i--) {
            var bit = (code >> i) & 1;
            if (node[bit] === null || typeof node[bit] === "number") {
                node[bit] = [null, null];
            }
            node = node[bit];
        }
        node[0] = sym; // leaf marker: node[0] = symbol, node[1] stays null
        node[1] = -1;  // sentinel
    }
})();

function huffmanDecode(bytes, off, len) {
    var result = [];
    var node = _huffRoot;
    for (var i = 0; i < len; i++) {
        var b = bytes[off + i];
        for (var j = 7; j >= 0; j--) {
            var bit = (b >> j) & 1;
            node = node[bit];
            if (node === null) return result.length > 0 ? String.fromCharCode.apply(null, result) : "";
            if (node[1] === -1) {
                // leaf
                var sym = node[0];
                if (sym === 256) return String.fromCharCode.apply(null, result); // EOS
                result.push(sym);
                node = _huffRoot;
            }
        }
    }
    return String.fromCharCode.apply(null, result);
}

// ── HPACK 静态表（HTTP/2 RFC 7541 Appendix A）──────────────────
var HPACK_STATIC = [
    null,
    [":authority",""], [":method","GET"], [":method","POST"],
    [":path","/"], [":path","/index.html"], [":scheme","http"],
    [":scheme","https"], [":status","200"], [":status","204"],
    [":status","206"], [":status","304"], [":status","400"],
    [":status","404"], [":status","500"], ["accept-charset",""],
    ["accept-encoding","gzip, deflate"], ["accept-language",""],
    ["accept-ranges",""], ["accept",""], ["access-control-allow-origin",""],
    ["age",""], ["allow",""], ["authorization",""], ["cache-control",""],
    ["content-disposition",""], ["content-encoding",""], ["content-language",""],
    ["content-length",""], ["content-location",""], ["content-range",""],
    ["content-type",""], ["cookie",""], ["date",""], ["etag",""],
    ["expect",""], ["expires",""], ["from",""], ["host",""],
    ["if-match",""], ["if-modified-since",""], ["if-none-match",""],
    ["if-range",""], ["if-unmodified-since",""], ["last-modified",""],
    ["link",""], ["location",""], ["max-forwards",""], ["proxy-authenticate",""],
    ["proxy-authorization",""], ["range",""], ["referer",""],
    ["refresh",""], ["retry-after",""], ["server",""],
    ["set-cookie",""], ["strict-transport-security",""],
    ["transfer-encoding",""], ["user-agent",""], ["vary",""],
    ["via",""], ["www-authenticate",""]
];

// ── HPACK 整数解码（多字节前缀编码）────────────────────────────
function readHpackInt(bytes, pos, end, prefixBits) {
    var mask = (1 << prefixBits) - 1;
    var val = bytes[pos] & mask;
    pos++;
    if (val < mask) return {val: val, pos: pos};
    var m = 0;
    while (pos < end) {
        var b = bytes[pos++];
        val += (b & 0x7f) << m;
        m += 7;
        if (!(b & 0x80)) break;
    }
    return {val: val, pos: pos};
}

// ── HPACK 字符串解码（支持 Huffman）─────────────────────────────
function readHpackStr(bytes, pos, end) {
    if (pos >= end) return {str: "", pos: pos};
    var isHuff = (bytes[pos] & 0x80) !== 0;
    var r = readHpackInt(bytes, pos, end, 7);
    var len = r.val;
    pos = r.pos;
    if (pos + len > end) len = end - pos;

    var s = "";
    if (isHuff) {
        s = huffmanDecode(bytes, pos, len);
    } else {
        for (var i = 0; i < len; i++) {
            var c = bytes[pos + i];
            s += (c >= 32 && c < 127) ? String.fromCharCode(c) : ".";
        }
    }
    return {str: s, pos: pos + len};
}

// ── HPACK 完整解码（含动态表）───────────────────────────────────
// dynTable: 数组，最新条目在 index 0，每个条目 = [name, value]
// 静态表索引 1-61，动态表索引从 62 开始
function lookupIndex(idx, dynTable) {
    if (idx > 0 && idx < HPACK_STATIC.length) {
        return HPACK_STATIC[idx];
    }
    var di = idx - HPACK_STATIC.length; // 62→0, 63→1, ...
    if (di >= 0 && di < dynTable.length) {
        return dynTable[di];
    }
    return null;
}

function decodeHpack(bytes, off, end, dynTable) {
    var headers = [], pos = off;
    try {
        while (pos < end) {
            var b = bytes[pos];
            if (b & 0x80) {
                // 索引头字段 (7-bit prefix)
                var r = readHpackInt(bytes, pos, end, 7);
                var idx = r.val; pos = r.pos;
                var entry = lookupIndex(idx, dynTable);
                if (entry) {
                    headers.push(entry[0] + ": " + entry[1]);
                } else {
                    headers.push("[idx " + idx + " ?]");
                }
            } else if ((b & 0xc0) === 0x40) {
                // 增量索引字面量 (6-bit prefix) → 解码后加入动态表
                var r1 = readHpackInt(bytes, pos, end, 6);
                var nameIdx = r1.val; pos = r1.pos;
                var name, val;
                if (nameIdx > 0) {
                    var ne = lookupIndex(nameIdx, dynTable);
                    name = ne ? ne[0] : ("?idx" + nameIdx);
                } else {
                    var rn = readHpackStr(bytes, pos, end);
                    name = rn.str; pos = rn.pos;
                }
                var rv = readHpackStr(bytes, pos, end);
                val = rv.str; pos = rv.pos;
                // 加入动态表（最新条目在最前面）
                dynTable.unshift([name, val]);
                headers.push(name + ": " + val);
            } else if ((b & 0xe0) === 0x20) {
                // 动态表大小更新 (5-bit prefix)
                var r2 = readHpackInt(bytes, pos, end, 5);
                pos = r2.pos;
                // 按新大小截断动态表（简化处理）
            } else {
                // 不索引 / never-indexed 字面量 (4-bit prefix) → 不加入动态表
                var r3 = readHpackInt(bytes, pos, end, 4);
                var nameIdx2 = r3.val; pos = r3.pos;
                var name2, val2;
                if (nameIdx2 > 0) {
                    var ne2 = lookupIndex(nameIdx2, dynTable);
                    name2 = ne2 ? ne2[0] : ("?idx" + nameIdx2);
                } else {
                    var rn2 = readHpackStr(bytes, pos, end);
                    name2 = rn2.str; pos = rn2.pos;
                }
                var rv2 = readHpackStr(bytes, pos, end);
                val2 = rv2.str; pos = rv2.pos;
                headers.push(name2 + ": " + val2);
            }
        }
    } catch(e) {
        headers.push("[decode error: " + e + "]");
    }
    return headers;
}

// ── gzip 解压 ─────────────────────────────────────────────────
var _inflateInit2 = null, _inflate = null, _inflateEnd = null;
(function() {
    var libz = Process.findModuleByName("libz.so");
    if (!libz) return;
    libz.enumerateExports().forEach(function(e) {
        if (e.name === "inflateInit2_") _inflateInit2 = new NativeFunction(e.address, 'int', ['pointer','int','pointer','int']);
        if (e.name === "inflate")       _inflate     = new NativeFunction(e.address, 'int', ['pointer','int']);
        if (e.name === "inflateEnd")    _inflateEnd  = new NativeFunction(e.address, 'int', ['pointer']);
    });
})();

function decompressGzip(bytes, offset, len) {
    if (!_inflateInit2) return null;
    try {
        var zs = Memory.alloc(128); zs.writeByteArray(new Array(128).fill(0));
        var src = Memory.alloc(len);
        for (var i = 0; i < len; i++) src.add(i).writeU8(bytes[offset + i]);
        var dstSize = Math.min(len * 20, 131072);
        var dst = Memory.alloc(dstSize);
        zs.writePointer(src);
        zs.add(8).writeU32(len);
        zs.add(24).writePointer(dst);
        zs.add(32).writeU32(dstSize);
        var ver = Memory.allocUtf8String("1.2.11");
        if (_inflateInit2(zs, 47, ver, 112) !== 0) return null;
        _inflate(zs, 4);
        _inflateEnd(zs);
        var totalOut = zs.add(40).readU32();
        if (totalOut > 0) return new Uint8Array(dst.readByteArray(totalOut));
    } catch(e) {}
    return null;
}

// ── 将字节转为可读文本 ────────────────────────────────────────
function bytesToText(bytes, off, len) {
    var s = "";
    for (var i = 0; i < len; i++) {
        var c = bytes[off + i];
        s += (c >= 32 && c < 127) ? String.fromCharCode(c) : ".";
    }
    return s;
}

// ── 跟踪活跃 stream 的 host（从 HEADERS 里提取 :authority）───
var streamHosts = {};

// ── HPACK 动态表（per connection+direction）─────────────────────
// HTTP/2 的 HPACK 编码器会把重复出现的头字段存入"动态表"
// 后续只用索引号引用，不再重传完整值
// 静态表 = 61 个预定义条目（索引 1-61）
// 动态表 = 索引从 62 开始，最新条目在最前面
var _dynTables = {};
function getDynTable(host, dir) {
    var key = (host || "?") + "|" + dir;
    if (!_dynTables[key]) _dynTables[key] = [];
    return _dynTables[key];
}

// ── 解析并打印 HTTP/2 帧 ──────────────────────────────────────
// dir 示例: "→ SEND" 或 "← RECV"
function parseH2(bytes, total, dir, host) {
    var dynTable = getDynTable(host, dir);
    var pos = 0;
    // 跳 connection preface
    if (total >= 24) {
        var pre = "";
        for (var i = 0; i < Math.min(24, total); i++) pre += String.fromCharCode(bytes[i]);
        if (pre === "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
            pos = 24;
        }
    }

    var connKey = host || "?";

    while (pos + 9 <= total) {
        var flen  = (bytes[pos]<<16) | (bytes[pos+1]<<8) | bytes[pos+2];
        var ftype = bytes[pos+3];
        var fflg  = bytes[pos+4];
        var fsid  = ((bytes[pos+5]&0x7f)<<24) | (bytes[pos+6]<<16) | (bytes[pos+7]<<8) | bytes[pos+8];
        pos += 9;
        if (flen > total - pos || flen > 131072) break;

        var streamKey = connKey + "#" + fsid;

        if (ftype === 0x01 && flen > 0) {
            // HEADERS 帧
            var padLen = 0, hdrOff = pos, hdrLen = flen;
            if (fflg & 0x08) { padLen = bytes[pos]; hdrOff++; hdrLen -= (1 + padLen); }
            if (fflg & 0x20) { hdrOff += 5; hdrLen -= 5; }

            var hdrs = decodeHpack(bytes, hdrOff, hdrOff + hdrLen, dynTable);

            // 提取 :authority 用于 stream 跟踪
            for (var hi = 0; hi < hdrs.length; hi++) {
                var m = hdrs[hi].match(/^:authority: (.+)/);
                if (m) streamHosts[streamKey] = m[1];
            }
            var sHost = streamHosts[streamKey] || host || "";

            // 显示 bili 相关的，或者未知 host 的发送请求
            if (sHost.indexOf("bili") !== -1 || (sHost === "" && dir.indexOf("SEND") !== -1)) {
                console.log("\n🔴 " + dir + " " + sHost + " [HEADERS stream=" + fsid + " flags=0x" + fflg.toString(16) + "]");
                for (var j = 0; j < hdrs.length; j++) {
                    console.log("  " + hdrs[j]);
                }
            }
        } else if (ftype === 0x00 && flen > 0) {
            // DATA 帧
            var sHost2 = streamHosts[streamKey] || host || "";
            if (sHost2.indexOf("bili") === -1 && sHost2 !== "") { pos += flen; continue; }

            var bodyBytes = bytes, bodyOff = pos, bodyLen = flen;
            var label = "";

            var gc = bytes[pos];
            var gl = (bytes[pos+1]<<24)|(bytes[pos+2]<<16)|(bytes[pos+3]<<8)|bytes[pos+4];
            if ((gc === 0 || gc === 1) && gl > 0 && gl <= flen - 5) {
                label = "gRPC";
            } else {
                label = "REST-BODY";
                if (bodyLen > 2 && bytes[bodyOff] === 0x1f && bytes[bodyOff+1] === 0x8b) {
                    var dec = decompressGzip(bytes, bodyOff, bodyLen);
                    if (dec) { bodyBytes = dec; bodyOff = 0; bodyLen = dec.length; label += "(gzip→" + bodyLen + "B)"; }
                }
            }

            if (label.indexOf("REST") !== -1) {
                var text = bytesToText(bodyBytes, bodyOff, bodyLen);
                console.log("\n🔴 " + dir + " " + sHost2 + " [DATA stream=" + fsid + " " + flen + "B " + label + "]");
                if (text.indexOf("=") !== -1 && text.indexOf("&") !== -1) {
                    var parts = text.split("&");
                    for (var pi = 0; pi < parts.length; pi++) {
                        console.log("  " + parts[pi]);
                    }
                } else {
                    console.log("  " + text.substring(0, 2000));
                }
            }
        }
        pos += flen;
    }
}

// ── 主处理函数 ────────────────────────────────────────────────
function handleTraffic(dir, host, bufPtr, len) {
    if (len <= 9) return;
    try {
        var bytes = new Uint8Array(bufPtr.readByteArray(len));

        if (len > 4) {
            var s4 = String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3]);
            if (s4 === "POST" || s4 === "GET " || s4 === "HTTP") {
                var text = bytesToText(bytes, 0, len);
                if (text.indexOf("bili") !== -1 || text.indexOf("reply") !== -1) {
                    console.log("\n🔴 " + dir + " " + (host||"") + " [HTTP/1.1 " + len + "B]");
                    console.log("  " + text.substring(0, 2000));
                }
                return;
            }
        }
        parseH2(bytes, len, dir, host);
    } catch(e) {}
}

// ── Hook libssl.so ───────────────────────────────────────────
function hookSsl(mod) {
    var writeAddr = null, readAddr = null, setHostAddr = null, getSnAddr = null;
    try {
        mod.enumerateExports().forEach(function(e) {
            if (e.name === "SSL_write")                writeAddr   = e.address;
            if (e.name === "SSL_read")                 readAddr    = e.address;
            if (e.name === "SSL_set_tlsext_host_name") setHostAddr = e.address;
            if (e.name === "SSL_get_servername")       getSnAddr   = e.address;
        });
    } catch(e) { return; }

    var getSn = getSnAddr ? new NativeFunction(getSnAddr, 'pointer', ['pointer','int']) : null;
    function getHost(ssl) {
        var k = ssl.toString();
        if (sslHostMap[k]) return sslHostMap[k];
        if (!getSn) return "";
        try { var p = getSn(ssl, 0); return p.isNull() ? "" : p.readCString(); } catch(e) { return ""; }
    }

    if (setHostAddr) {
        Interceptor.attach(setHostAddr, {
            onEnter: function(args) {
                try { sslHostMap[args[0].toString()] = args[1].readCString(); } catch(e) {}
            }
        });
    }
    if (writeAddr) {
        Interceptor.attach(writeAddr, {
            onEnter: function(args) {
                var len = args[2].toInt32();
                if (len > 0 && len <= 131072) handleTraffic("→ SEND", getHost(args[0]), args[1], len);
            }
        });
    }
    if (readAddr) {
        Interceptor.attach(readAddr, {
            onEnter: function(args) { this.ssl = args[0]; this.buf = args[1]; },
            onLeave: function(retval) {
                var len = retval.toInt32();
                if (len > 0) handleTraffic("← RECV", getHost(this.ssl), this.buf, len);
            }
        });
    }
    console.log("[+] Hooked " + mod.name + " (" + mod.path.split("/").slice(-3).join("/") + ")");
}

// ── 轮询加载 ─────────────────────────────────────────────────
var hookedPaths = {};
function tryHookAll() {
    Process.enumerateModules().forEach(function(mod) {
        if (mod.name === "libssl.so" && !hookedPaths[mod.path]) {
            hookedPaths[mod.path] = true;
            hookSsl(mod);
        }
    });
}
tryHookAll();
var cnt = 0;
var poller = setInterval(function() { tryHookAll(); if (++cnt >= 20) clearInterval(poller); }, 500);

console.log("[*] capture_comment.js v3 ready — Huffman + 动态表解码已启用");
console.log("[*] 等待发评论，会打印完整 HEADERS + BODY + RESPONSE");
