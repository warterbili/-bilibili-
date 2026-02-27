/**
 * hook_st.js
 * ==========
 * Hook LibBili.st() 的 Java 层，捕获三个参数和返回值。
 *
 * 从 jadx 分析得知调用方式：
 *   LibBili.st(nr2.a.f367438a.a(), linkedHashMap, "ec01")
 *
 * 用法（spawn 模式，配合 bypass.js）：
 *   frida -U -f tv.danmaku.bili -l bypass.js -l hook_st.js
 */

console.log("[hook_st] 等待 5 秒让 App 完成启动...");

setTimeout(function () {
    Java.perform(function () {
        var LibBili = Java.use("com.bilibili.nativelibrary.LibBili");

        // 枚举 LibBili 所有方法，确认 st 的签名
        console.log("=== LibBili 所有方法 ===");
        LibBili.class.getDeclaredMethods().forEach(function (m) {
            console.log("  " + m);
        });
        console.log("========================\n");

        // st 有两个重载：
        //   public static byte[] st(byte[], Map, String)          ← 公开包装
        //   static native byte[] st(byte[], SortedMap, String)    ← native 实现
        // hook 公开版本，能看到原始 Map 参数
        try {
            LibBili.st.overload(
                "[B",
                "java.util.Map",
                "java.lang.String"
            ).implementation = function (param1, param2, param3) {
                console.log("┌─── [LibBili.st] 被调用 ───");

                // 参数1：byte[]（nr2.a.f367438a.a() 的返回值）
                console.log("│ param1 (byte[]):");
                if (param1) {
                    var len1 = param1.length;
                    console.log("│   length = " + len1);
                    var hex1 = "";
                    for (var i = 0; i < len1 && i < 64; i++) {
                        var b = param1[i] & 0xff;
                        hex1 += ("0" + b.toString(16)).slice(-2);
                    }
                    console.log("│   hex = " + hex1 + (len1 > 64 ? "..." : ""));
                    // 尝试当 UTF-8 字符串读
                    try {
                        var str1 = Java.use("java.lang.String").$new(param1, "UTF-8");
                        console.log("│   utf8 = " + str1.toString().substring(0, 120));
                    } catch (e2) {}
                } else {
                    console.log("│   null");
                }

                // 参数2：Map（context 信息）
                console.log("│ param2 (Map):");
                if (param2) {
                    var it2 = param2.entrySet().iterator();
                    while (it2.hasNext()) {
                        var entry = it2.next();
                        var k = entry.getKey();
                        var v = entry.getValue();
                        console.log("│   " + k + " = " + (v ? v.toString().substring(0, 100) : "null"));
                    }
                } else {
                    console.log("│   null");
                }

                // 参数3：key_id 字符串
                console.log("│ param3 (String): " + param3);

                // 调用原始方法
                var result = this.st(param1, param2, param3);

                // 返回值：byte[]
                console.log("│ return (byte[]):");
                if (result) {
                    var len = result.length;
                    console.log("│   length = " + len);
                    var hex = "";
                    for (var i = 0; i < len && i < 64; i++) {
                        var b = result[i] & 0xff;
                        hex += ("0" + b.toString(16)).slice(-2);
                    }
                    console.log("│   hex = " + hex + (len > 64 ? "..." : ""));
                } else {
                    console.log("│   null");
                }

                console.log("└────────────────────────────\n");
                return result;
            };
            console.log("[hook_st] st(byte[], Map, String) hook 成功");
        } catch (e) {
            console.log("[hook_st] hook 失败: " + e);
        }
    });
}, 5000);
