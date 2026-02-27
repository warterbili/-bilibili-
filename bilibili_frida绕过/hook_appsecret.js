// hook_appsecret.js - 直接读取 FUN_00118ff0 的 param_4（appSecret 的 4 个 uint32_t）
// Ghidra 地址 0x118ff0，Ghidra 基址 0x100000
// 文件偏移 = 0x118ff0 - 0x100000 = 0x18ff0
// 运行时地址 = libbili.so base + 0x18ff0

var FILE_OFFSET = 0x18ff0;

function toHex8(n) {
    return ('00000000' + (n >>> 0).toString(16)).slice(-8);
}

function hookMd5Func(libbiliBase) {
    var targetAddr = libbiliBase.add(FILE_OFFSET);
    console.log("[+] FUN_00118ff0 运行时地址: " + targetAddr);

    Interceptor.attach(targetAddr, {
        onEnter: function(args) {
            // param_1 = args[0] = 输出 buffer
            // param_2 = args[1] = sorted_params 字符串指针
            // param_3 = args[2] = 字符串长度
            // param_4 = args[3] = 指向 4 个 uint32_t 的 buffer（appSecret）

            try {
                // 读 sorted_params 字符串
                var len = args[2].toInt32();
                var paramStr = args[1].readUtf8String(Math.min(len, 500));
                console.log("\n[+] FUN_00118ff0 调用");
                console.log("[*] sorted_params (" + len + "B): " + paramStr);
            } catch(e) {
                console.log("[*] 读 sorted_params 失败: " + e);
            }

            try {
                // 读 4 个 uint32_t = appSecret
                var v0 = args[3].readU32();
                var v1 = args[3].add(4).readU32();
                var v2 = args[3].add(8).readU32();
                var v3 = args[3].add(12).readU32();

                var appSecret = toHex8(v0) + toHex8(v1) + toHex8(v2) + toHex8(v3);
                console.log("[!!!] appSecret = " + appSecret);
            } catch(e) {
                console.log("[*] 读 appSecret 失败: " + e);
            }
        },
        onLeave: function(retval) {
            // 无返回值（void 函数），结果写入 param_1 指向的 buffer
        }
    });

    console.log("[+] Hook 已附加，发一条评论触发...");
}

// ── 等 libbili.so 加载 ────────────────────────────────────────
var hooked = false;
function tryHook() {
    if (hooked) return;
    var mod = Process.findModuleByName("libbili.so");
    if (!mod) return;
    hooked = true;
    console.log("[+] libbili.so base: " + mod.base);
    hookMd5Func(mod.base);
}

tryHook();
var count = 0;
var poller = setInterval(function() {
    tryHook();
    if (++count >= 30) clearInterval(poller);
}, 500);

console.log("[*] hook_appsecret.js ready");
