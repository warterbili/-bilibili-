/**
 * trace_access_token.js
 * =====================
 * 搜索 access_key / refresh_token 相关的类名，找到 token 管理的入口。
 *
 * 用法：
 *   frida -U -f tv.danmaku.bili -l bypass.js -l trace_access_token.js
 */

console.log("[trace_access] 等待 5 秒让 App 完成启动...");

setTimeout(function() {
    Java.perform(function() {

        // ═══════════════════════════════════════
        // 1. 搜索已加载类中 token/auth 相关的
        // ═══════════════════════════════════════
        console.log("\n=== 搜索 token/auth 相关类 ===");
        Java.enumerateLoadedClasses({
            onMatch: function(name) {
                var lower = name.toLowerCase();
                if ((lower.indexOf("refreshtoken") !== -1
                    || lower.indexOf("refresh_token") !== -1
                    || lower.indexOf("accesstoken") !== -1
                    || lower.indexOf("access_token") !== -1
                    || lower.indexOf("biliauth") !== -1)
                    && lower.indexOf("facebook") === -1
                    && lower.indexOf("sina") === -1) {
                    console.log("[class] " + name);
                }
            },
            onComplete: function() { console.log("=== 搜索完成 ===\n"); }
        });
    });
}, 5000);
