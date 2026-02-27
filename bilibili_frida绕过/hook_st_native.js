/**
 * hook_st_native.js
 * =================
 * Native hook LibBili.st() 的核心 HMAC 函数，抓取 key / input / output。
 *
 * 目标函数：FUN_001a6bc8（Ghidra 地址），文件偏移 0xa6bc8
 * 签名：(data, data_len, key, key_len, output, &out_len)
 *
 * 同时 hook FUN_001a606c（Map 序列化），文件偏移 0xa606c
 *
 * 用法：
 *   frida -U -f tv.danmaku.bili -l bypass.js -l hook_st_native.js
 *   然后在 REPL 中手动调用 st() 触发
 */

// 等 libbili.so 加载
function waitForLibbili(callback) {
    var mod = Process.findModuleByName("libbili.so");
    if (mod) {
        callback(mod.base);
        return;
    }
    var timer = setInterval(function () {
        mod = Process.findModuleByName("libbili.so");
        if (mod) {
            clearInterval(timer);
            callback(mod.base);
        }
    }, 500);
}

function hexdump_bytes(ptr, len) {
    var hex = "";
    for (var i = 0; i < len && i < 128; i++) {
        hex += ("0" + (ptr.add(i).readU8()).toString(16)).slice(-2);
    }
    return hex + (len > 128 ? "..." : "");
}

function try_read_utf8(ptr, len) {
    try {
        return ptr.readUtf8String(len);
    } catch (e) {
        return "(not utf8)";
    }
}

setTimeout(function () {
    waitForLibbili(function (base) {
        console.log("[+] libbili.so base = " + base);

        // ═══════════════════════════════════════════════════
        // Hook FUN_001a6bc8 — 核心 HMAC 签名函数
        // (data, data_len, key, key_len, output_buf, &out_len)
        // ═══════════════════════════════════════════════════
        var hmac_offset = 0xa6bc8;
        var hmac_addr = base.add(hmac_offset);
        console.log("[+] HMAC func @ " + hmac_addr + " (offset +0x" + hmac_offset.toString(16) + ")");

        Interceptor.attach(hmac_addr, {
            onEnter: function (args) {
                this.data = args[0];
                this.data_len = args[1].toInt32();
                this.key = args[2];
                this.key_len = args[3].toInt32();
                this.output = args[4];
                this.out_len_ptr = args[5];

                console.log("\n┌─── [HMAC] FUN_001a6bc8 ───");
                console.log("│ key_len = " + this.key_len);
                console.log("│ key_hex = " + hexdump_bytes(this.key, this.key_len));
                console.log("│ key_str = " + try_read_utf8(this.key, this.key_len));
                console.log("│ data_len = " + this.data_len);
                console.log("│ data_hex = " + hexdump_bytes(this.data, this.data_len));
            },
            onLeave: function (retval) {
                var out_len = this.out_len_ptr.readU32();
                console.log("│ out_len = " + out_len);
                console.log("│ output  = " + hexdump_bytes(this.output, out_len));
                console.log("└────────────────────────────\n");
            }
        });

        console.log("[+] HMAC hook 就绪");
        console.log("[*] 在 REPL 中粘贴以下代码触发 st():\n");
        console.log('Java.perform(function() {');
        console.log('    var nr2a = Java.use("nr2.a");');
        console.log('    var field = nr2a.class.getDeclaredField("a");');
        console.log('    field.setAccessible(true);');
        console.log('    var inst = Java.cast(field.get(null), nr2a);');
        console.log('    var bytes = inst.a();');
        console.log('    var LibBili = Java.use("com.bilibili.nativelibrary.LibBili");');
        console.log('    var HashMap = Java.use("java.util.HashMap");');
        console.log('    var map = HashMap.$new();');
        console.log('    map.put("ts", "" + Math.floor(Date.now()/1000));');
        console.log('    var r = LibBili.st(bytes, map, "ec01");');
        console.log('    console.log("st() done, result len=" + (r ? r.length : "null"));');
        console.log('});');
    });
}, 3000);
