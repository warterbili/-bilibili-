// ssl_hook.js v3 - 专注捕获评论/有效流量，过滤噪音
// 配合 bypass.js 使用，无 Java.perform

var sslHostMap = {};

// ── gzip 解压（使用系统 libz.so）────────────────────────────
var _inflateInit2 = null, _inflate = null, _inflateEnd = null;
(function() {
    var libz = Process.findModuleByName("libz.so");
    if (!libz) return;
    libz.enumerateExports().forEach(function(e) {
        if (e.name === "inflateInit2_") _inflateInit2 = new NativeFunction(e.address, 'int', ['pointer','int','pointer','int']);
        if (e.name === "inflate")       _inflate     = new NativeFunction(e.address, 'int', ['pointer','int']);
        if (e.name === "inflateEnd")    _inflateEnd  = new NativeFunction(e.address, 'int', ['pointer']);
    });
    if (_inflateInit2) console.log("[+] zlib gzip decompression ready");
})();

function decompressGzip(srcBytes, offset, len) {
    if (!_inflateInit2 || !_inflate || !_inflateEnd) return null;
    try {
        // z_stream on ARM64: next_in@0, avail_in@8, total_in@16,
        //                    next_out@24, avail_out@32, total_out@40
        var zs = Memory.alloc(128); zs.writeByteArray(new Array(128).fill(0));
        var src = Memory.alloc(len);
        for (var i = 0; i < len; i++) src.add(i).writeU8(srcBytes[offset + i]);
        var dstSize = Math.min(len * 20, 65536);
        var dst = Memory.alloc(dstSize);
        zs.writePointer(src);               // next_in
        zs.add(8).writeU32(len);            // avail_in
        zs.add(24).writePointer(dst);       // next_out
        zs.add(32).writeU32(dstSize);       // avail_out
        // wbits=47 = 15+32: gzip decode mode
        var ver = Memory.allocUtf8String("1.2.11");
        if (_inflateInit2(zs, 47, ver, 112) !== 0) return null;
        var ret = _inflate(zs, 4); // Z_FINISH=4
        _inflateEnd(zs);
        var totalOut = zs.add(40).readU32();
        if (totalOut > 0) return new Uint8Array(dst.readByteArray(totalOut));
    } catch(e) {}
    return null;
}

// ── Protobuf 解析 ─────────────────────────────────────────────
function decodeProto(bytes, offset, limit) {
    var result = [], pos = offset;
    try {
        while (pos < limit && result.length < 20) {
            var b = bytes[pos++] & 0xff;
            var field = b >>> 3, wire = b & 7;
            if (wire === 0) {
                var v = 0, sh = 0, bv;
                do { bv = bytes[pos++] & 0xff; v |= (bv & 0x7f) << sh; sh += 7; } while (bv & 0x80);
                result.push("  f" + field + "(int)=" + v);
            } else if (wire === 2) {
                var l = 0, sh = 0, bv;
                do { bv = bytes[pos++] & 0xff; l |= (bv & 0x7f) << sh; sh += 7; } while (bv & 0x80);
                var s = "";
                for (var i = 0; i < Math.min(l, 120); i++) {
                    var c = bytes[pos + i] & 0xff;
                    s += (c >= 32 && c < 127) ? String.fromCharCode(c) : ".";
                }
                result.push("  f" + field + "(str/" + l + ")=\"" + s + "\"");
                pos += l;
            } else if (wire === 5) { pos += 4; }
              else if (wire === 1) { pos += 8; }
              else break;
        }
    } catch(e) {}
    return result.join("\n");
}

// ── HTTP/2 帧解析，返回是否有内容 ────────────────────────────
function parseAndLog(bytes, total, prefix) {
    var pos = 0, printed = false;
    // 检测 HTTP/1.1 文本协议（POST/GET/HTTP 开头）
    if (total > 4) {
        var s4 = String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3]);
        if (s4 === "POST" || s4 === "GET " || s4 === "HTTP") {
            // 先读头部（含 \r\n 以便检测 URL 和 Content-Encoding）
            var hdr = "";
            for (var i = 0; i < Math.min(total, 2048); i++) {
                var c = bytes[i];
                hdr += (c >= 32 && c < 127 || c === 10 || c === 13) ? String.fromCharCode(c) : ".";
            }
            // 检测 /reply 路径 或 body 中 message=
            var isReply = hdr.indexOf("/reply") !== -1 || hdr.indexOf("message=") !== -1;
            if (!isReply) return false;

            console.log("\n🔴 " + prefix + " [HTTP] " + total + "B");
            console.log("  " + hdr.substring(0, 300).replace(/\r\n/g, " | "));

            // 找 body 起始（\r\n\r\n 之后）
            var bodyStart = -1;
            for (var i = 0; i < total - 3; i++) {
                if (bytes[i]===13 && bytes[i+1]===10 && bytes[i+2]===13 && bytes[i+3]===10) {
                    bodyStart = i + 4; break;
                }
            }
            if (bodyStart !== -1 && bodyStart < total) {
                var bodyLen = total - bodyStart;
                // 尝试 gzip 解压
                if (bytes[bodyStart] === 0x1f && bytes[bodyStart+1] === 0x8b) {
                    var dec = decompressGzip(bytes, bodyStart, bodyLen);
                    if (dec) {
                        var ds = "";
                        for (var i = 0; i < Math.min(dec.length, 800); i++) {
                            var c = dec[i]; ds += (c >= 32 && c < 127) ? String.fromCharCode(c) : ".";
                        }
                        console.log("  ★ body(解压): " + ds);
                    } else {
                        console.log("  body gzip 解压失败, len=" + bodyLen);
                    }
                } else {
                    // 明文 body
                    var bs = "";
                    for (var i = 0; i < Math.min(bodyLen, 800); i++) {
                        var c = bytes[bodyStart+i]; bs += (c >= 32 && c < 127) ? String.fromCharCode(c) : ".";
                    }
                    console.log("  ★ body: " + bs);
                }
            }
            return true;
        }
    }
    // 跳过 HTTP/2 连接序言
    if (total >= 24) {
        var pre = "";
        for (var i = 0; i < 24; i++) pre += String.fromCharCode(bytes[i]);
        if (pre === "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") pos = 24;
    }
    while (pos + 9 <= total) {
        var flen  = (bytes[pos] << 16) | (bytes[pos+1] << 8) | bytes[pos+2];
        var ftype = bytes[pos+3];
        var fflg  = bytes[pos+4];
        var fsid  = ((bytes[pos+5] & 0x7f) << 24) | (bytes[pos+6] << 16) | (bytes[pos+7] << 8) | bytes[pos+8];
        pos += 9;
        if (flen > total - pos || flen > 65536) break;
        // 只处理 DATA 帧（type=0），跳过 SETTINGS/PING/HEADERS（无法解 HPACK）
        if (ftype === 0x00 && flen >= 5) {
            var gc = bytes[pos];
            var gl = (bytes[pos+1]<<24)|(bytes[pos+2]<<16)|(bytes[pos+3]<<8)|bytes[pos+4];
            if (gc === 0 && gl > 0 && gl <= flen - 5) {
                // 非压缩 gRPC，直接解析 Protobuf
                var pb = decodeProto(bytes, pos + 5, pos + 5 + gl);
                if (pb) {
                    if (!printed) {
                        console.log("\n" + prefix + " [gRPC DATA stream=" + fsid + " " + gl + "B]");
                        printed = true;
                    }
                    console.log(pb);
                }
            } else if (gc === 1 && gl > 0 && gl <= flen - 5) {
                // 压缩 gRPC：先 gzip 解压，再解析 Protobuf
                var dec = decompressGzip(bytes, pos + 5, gl);
                if (dec) {
                    var pb = decodeProto(dec, 0, dec.length);
                    if (!printed) {
                        console.log("\n" + prefix + " [gRPC DATA(gz) stream=" + fsid + " " + gl + "B→" + dec.length + "B]");
                        printed = true;
                    }
                    if (pb) console.log(pb);
                } else {
                    var hex = "";
                    for (var hi = 0; hi < Math.min(gl, 32); hi++) {
                        var hb = bytes[pos + 5 + hi].toString(16);
                        hex += (hb.length < 2 ? "0" : "") + hb + " ";
                    }
                    console.log("\n" + prefix + " [gRPC DATA(gz) stream=" + fsid + " decompress FAIL] hex=" + hex);
                }
            } else if (flen > 4) {
                // 非 gRPC 的 H2 DATA 帧（普通 REST 请求体）
                var bodyBytes = bytes, bodyOff = pos, bodyLen2 = flen;
                var decoded2 = null;
                // gzip body
                if (bytes[pos] === 0x1f && bytes[pos+1] === 0x8b) {
                    decoded2 = decompressGzip(bytes, pos, flen);
                    if (decoded2) { bodyBytes = decoded2; bodyOff = 0; bodyLen2 = decoded2.length; }
                }
                // 读成可读字符串
                var ds2 = "", rdbl = 0;
                for (var di = 0; di < Math.min(bodyLen2, 1200); di++) {
                    var dc = bodyBytes[bodyOff + di];
                    if ((dc >= 32 && dc < 127) || dc === 10 || dc === 13) { ds2 += String.fromCharCode(dc); rdbl++; }
                    else ds2 += ".";
                }
                // 可读性 >50% 或包含关键字，就显示
                var hasKw = ds2.indexOf("message") !== -1 || ds2.indexOf("reply") !== -1 ||
                            ds2.indexOf("comment") !== -1 || ds2.indexOf("oid") !== -1;
                if (hasKw || rdbl / Math.min(bodyLen2, 200) > 0.5) {
                    if (!printed) {
                        var tag = decoded2 ? flen + "B→" + bodyLen2 + "B" : flen + "B";
                        console.log("\n🔴 " + prefix + " [H2 DATA stream=" + fsid + " " + tag + "]");
                        printed = true;
                    }
                    console.log("  " + ds2.substring(0, 1000));
                }
            }
        }
        pos += flen;
    }
    return printed;
}

// ── 统计可读字节比例 ──────────────────────────────────────────
function readableRatio(bytes, len) {
    var readable = 0, check = Math.min(len, 200);
    for (var i = 0; i < check; i++) {
        var c = bytes[i];
        if ((c >= 32 && c < 127) || c === 10 || c === 13) readable++;
    }
    return readable / check;
}

// ── 主日志函数 ────────────────────────────────────────────────
function logTraffic(dir, host, bufPtr, len) {
    // 跳过心跳/PING 小包
    if (len <= 20) return;
    // 跳过纯 SETTINGS 帧（通常 9+6=15 字节或 9 字节）
    if (len <= 30) return;

    var label = dir + (host || "?");
    try {
        var bytes = new Uint8Array(bufPtr.readByteArray(len));

        // 检查是否有足够可读内容
        var ratio = readableRatio(bytes, len);

        // 尝试解析 HTTP/2 DATA 帧或 HTTP/1.1
        var showed = parseAndLog(bytes, len, label);

        // 如果没有 gRPC/HTTP 内容，但可读性高（REST JSON 等），也显示
        if (!showed && ratio > 0.6 && len > 50) {
            var s = "";
            for (var i = 0; i < Math.min(len, 1000); i++) {
                var c = bytes[i]; s += (c >= 32 && c < 127) ? String.fromCharCode(c) : ".";
            }
            // 只显示含关键词的
            if (s.indexOf("message") !== -1 || s.indexOf("reply") !== -1 ||
                s.indexOf("comment") !== -1 || s.indexOf("code") !== -1 ||
                s.indexOf("bilibili") !== -1 || s.indexOf("grpc") !== -1) {
                console.log("\n" + label + " [TEXT " + len + "B]");
                console.log("  " + s.substring(0, 500));
            }
        }
    } catch(e) {}
}

// ── 钩住一个 libssl.so 实例 ───────────────────────────────────
function hookSslLib(mod) {
    var writeAddr = null, readAddr = null, setHostAddr = null, getSnAddr = null;
    try {
        mod.enumerateExports().forEach(function(e) {
            if (e.name === "SSL_write")                writeAddr   = e.address;
            if (e.name === "SSL_read")                 readAddr    = e.address;
            if (e.name === "SSL_set_tlsext_host_name") setHostAddr = e.address;
            if (e.name === "SSL_get_servername")       getSnAddr   = e.address;
        });
    } catch(e) { return; }

    var getSn = getSnAddr ? new NativeFunction(getSnAddr, 'pointer', ['pointer', 'int']) : null;
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
                if (len <= 0 || len > 131072) return;
                logTraffic("→", getHost(args[0]), args[1], len);
            }
        });
        console.log("[+] SSL_write in " + mod.name + " (" + mod.path.split("/").slice(-3,-1).join("/") + ")");
    }
    if (readAddr) {
        Interceptor.attach(readAddr, {
            onEnter: function(args) { this.ssl = args[0]; this.buf = args[1]; },
            onLeave: function(retval) {
                var len = retval.toInt32();
                if (len <= 0) return;
                logTraffic("←", getHost(this.ssl), this.buf, len);
            }
        });
        console.log("[+] SSL_read  in " + mod.name + " (" + mod.path.split("/").slice(-3,-1).join("/") + ")");
    }
}

// ── 轮询加载所有 libssl.so（含延迟加载的 B站版本）────────────
var hookedPaths = {};
function tryHookAll() {
    Process.enumerateModules().forEach(function(mod) {
        if (mod.name === "libssl.so" && !hookedPaths[mod.path]) {
            hookedPaths[mod.path] = true;
            hookSslLib(mod);
        }
    });
}
tryHookAll();
var checkCount = 0;
var poller = setInterval(function() {
    tryHookAll();
    if (++checkCount >= 20) clearInterval(poller);
}, 500);

console.log("[*] ssl_hook.js v3 ready — 只显示评论/有效内容，过滤心跳噪音");
