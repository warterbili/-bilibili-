// find_okhttp.js - 枚举 B站内的 OkHttp 相关类名
// frida -U -f tv.danmaku.bili -l bypass.js -l find_okhttp.js

Java.perform(function () {
    console.log("[*] 开始枚举 OkHttp 相关类，请稍候（10~30秒）...");

    // attach 模式下 App 已在运行，直接枚举
    var found = [];
    Java.enumerateLoadedClasses({
        onMatch: function (name) {
            var lower = name.toLowerCase();
            if (lower.indexOf("okhttp") !== -1) {
                found.push(name);
            }
        },
        onComplete: function () {
            console.log("\n[+] 找到 " + found.length + " 个 OkHttp 相关类：");
            found.forEach(function (c) { console.log("  " + c); });
            console.log("[*] 枚举完成");
        }
    });
});
