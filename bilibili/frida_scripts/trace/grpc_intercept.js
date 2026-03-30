// grpc_intercept.js - 拦截 B站 gRPC 明文（OkHttpClient.newCall 版）
// 使用方式（attach 到已运行的进程）：
// frida -U -p <PID> -l bypass.js -l grpc_intercept.js

Java.perform(function () {
    console.log("[*] grpc_intercept.js loaded");

    // ── 工具：简易 Protobuf 解析 ──────────────────────────────
    function decodeProtobufRaw(bytes) {
        if (!bytes || bytes.length === 0) return "(empty)";
        var result = [];
        var pos = 0;
        try {
            while (pos < bytes.length && result.length < 30) {
                var b = bytes[pos] & 0xff;
                pos++;
                var fieldNum = b >>> 3;
                var wireType = b & 0x07;
                if (wireType === 0) {
                    var val = 0, shift = 0, bv;
                    do { bv = bytes[pos++] & 0xff; val |= (bv & 0x7f) << shift; shift += 7; } while (bv & 0x80);
                    result.push("  f" + fieldNum + "(varint) = " + val);
                } else if (wireType === 2) {
                    var len = 0, shift = 0, bv;
                    do { bv = bytes[pos++] & 0xff; len |= (bv & 0x7f) << shift; shift += 7; } while (bv & 0x80);
                    var chunk = bytes.slice(pos, pos + len);
                    pos += len;
                    var str = "";
                    for (var i = 0; i < Math.min(chunk.length, 64); i++) {
                        var c = chunk[i] & 0xff;
                        str += (c >= 32 && c < 127) ? String.fromCharCode(c) : ".";
                    }
                    result.push("  f" + fieldNum + "(str/" + len + ") = \"" + str + "\"");
                } else if (wireType === 1) { pos += 8; result.push("  f" + fieldNum + "(64bit)"); }
                  else if (wireType === 5) { pos += 4; result.push("  f" + fieldNum + "(32bit)"); }
                  else break;
            }
        } catch(e) {}
        return result.join("\n") || "(parse error)";
    }

    function parseGrpcBody(jbytes) {
        if (!jbytes || jbytes.length < 5) return;
        var bytes = [];
        for (var i = 0; i < jbytes.length; i++) bytes.push(jbytes[i] & 0xff);
        var compressed = bytes[0];
        var msgLen = (bytes[1] << 24) | (bytes[2] << 16) | (bytes[3] << 8) | bytes[4];
        console.log("  [gRPC] compressed=" + compressed + " msgLen=" + msgLen);
        if (msgLen > 0 && msgLen <= 65536) {
            var msg = bytes.slice(5, 5 + msgLen);
            console.log("  [Protobuf]\n" + decodeProtobufRaw(msg));
        }
    }

    // ── Hook OkHttpClient.newCall ─────────────────────────────
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");

        OkHttpClient.newCall.implementation = function (request) {
            var url = request.url().toString();
            var method = request.method();

            // 只记录 B站相关流量
            var isBili = url.indexOf("bilibili") !== -1 ||
                         url.indexOf("biliapi") !== -1 ||
                         url.indexOf("biligame") !== -1;

            if (isBili) {
                console.log("\n══════════════════════════════════════════");
                console.log("[REQ] " + method + " " + url);

                // 打印 headers
                try {
                    console.log("  Headers: " + request.headers().toString().trim());
                } catch(e) {}

                // 只记录 Content-Type，不读取 body（读取会消费 body 导致请求失败）
                var body = request.body();
                if (body !== null) {
                    try {
                        var ct = body.contentType();
                        console.log("  Content-Type: " + (ct ? ct.toString() : "null"));
                    } catch(e) {}
                }
            }

            // 调用原始 newCall，获取 Call 对象
            var call = this.newCall(request);

            if (isBili) {
                // 打印真实 Call 类名（确认混淆后的类名）
                console.log("  [Call class] " + call.$className);
            }

            return call;
        };

        console.log("[+] OkHttpClient.newCall hooked");
    } catch(e) {
        console.log("[-] OkHttpClient.newCall hook failed: " + e);
    }

    console.log("[*] 准备就绪，请在 B站 App 发一条评论...");
});
