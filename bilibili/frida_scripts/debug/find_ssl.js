// find_ssl.js - 枚举所有已加载模块，查找 SSL_write / SSL_read
// 纯原生，无 Java.perform
// 用法：frida -U -f tv.danmaku.bili -l bypass.js -l find_ssl.js

var found = [];

Process.enumerateModules().forEach(function(mod) {
    try {
        mod.enumerateExports().forEach(function(e) {
            if (e.name === "SSL_write" || e.name === "SSL_read" ||
                e.name === "SSL_write_ex" || e.name === "SSL_read_ex") {
                found.push({ lib: mod.name, path: mod.path, name: e.name, addr: e.address });
            }
        });
    } catch(e) {}
});

if (found.length > 0) {
    console.log("[+] 找到 SSL 函数：");
    found.forEach(function(f) {
        console.log("  " + f.name + " @ " + f.addr + "  lib=" + f.lib);
        console.log("    path=" + f.path);
    });
} else {
    console.log("[-] 未找到 SSL_write/SSL_read，可能还未加载，等待 10 秒后重试...");
    // 等待网络库加载后再找
    setTimeout(function() {
        Process.enumerateModules().forEach(function(mod) {
            try {
                mod.enumerateExports().forEach(function(e) {
                    if (e.name === "SSL_write" || e.name === "SSL_read") {
                        console.log("[+] (延迟) " + e.name + " in " + mod.name + " @ " + e.address);
                    }
                });
            } catch(e) {}
        });
    }, 10000);
}

console.log("[*] 已加载模块中含 ssl/crypto/conscrypt 的：");
Process.enumerateModules().forEach(function(mod) {
    var low = mod.name.toLowerCase();
    if (low.indexOf("ssl") !== -1 || low.indexOf("crypto") !== -1 ||
        low.indexOf("conscrypt") !== -1 || low.indexOf("boring") !== -1) {
        console.log("  " + mod.name + "  " + mod.path);
    }
});
