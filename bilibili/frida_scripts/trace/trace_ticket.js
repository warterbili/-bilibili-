/**
 * trace_ticket.js
 * ===============
 * 追踪 x-bili-ticket 的来源链路。
 *
 * Hook SharedPreferences getString/putString，捕获 JWT 缓存读写。
 * 延迟 5 秒后挂载，避免与 App 启动阶段的反检测冲突。
 *
 * 用法（两种方式）：
 *
 *   方式 1：和 bypass.js 一起 spawn（推荐）
 *     frida -U -f tv.danmaku.bili -l bypass.js -l trace_ticket.js
 *
 *   方式 2：App 已启动后 attach
 *     frida -U tv.danmaku.bili -l trace_ticket.js
 */

console.log("[trace_ticket] 等待 5 秒让 App 完成启动...");

setTimeout(function () {
    Java.perform(function () {
        console.log("[trace_ticket] 开始挂载 SP hook...\n");

        // ══════════════════════════════════════════════════════
        // 1. Hook SharedPreferences —— 读取（getString）
        // ══════════════════════════════════════════════════════
        var SPImpl = Java.use("android.app.SharedPreferencesImpl");
        SPImpl.getString.implementation = function (key, defValue) {
            var value = this.getString(key, defValue);
            if (value && value.toString().startsWith("eyJ")) {
                console.log("┌─── [SP.getString] JWT detected ───");
                console.log("│ key   = " + key);
                console.log("│ value = " + value.toString().substring(0, 80) + "...");
                console.log("│ stack:");
                var stack = Java.use("android.util.Log").getStackTraceString(
                    Java.use("java.lang.Throwable").$new()
                );
                var lines = stack.split("\n").slice(0, 15);
                lines.forEach(function (line) {
                    console.log("│   " + line.trim());
                });
                console.log("└────────────────────────────────────\n");
            }
            return value;
        };

        // ══════════════════════════════════════════════════════
        // 2. Hook SharedPreferences —— 写入（putString）
        // ══════════════════════════════════════════════════════
        var Editor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
        Editor.putString.implementation = function (key, value) {
            if (value && value.toString().startsWith("eyJ")) {
                console.log("┌─── [SP.putString] JWT写入 ─────────");
                console.log("│ key   = " + key);
                console.log("│ value = " + value.toString().substring(0, 80) + "...");
                console.log("│ stack:");
                var stack = Java.use("android.util.Log").getStackTraceString(
                    Java.use("java.lang.Throwable").$new()
                );
                var lines = stack.split("\n").slice(0, 15);
                lines.forEach(function (line) {
                    console.log("│   " + line.trim());
                });
                console.log("└────────────────────────────────────\n");
            }
            return this.putString(key, value);
        };

        console.log("[trace_ticket] Hook 已就绪（SP getString + putString）");
        console.log("[trace_ticket] 现在进入任意视频页面触发请求即可\n");
    });
}, 5000);
