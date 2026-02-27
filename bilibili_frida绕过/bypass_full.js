// bypass_full.js v4 - B站 Frida 完整绕过
// 核心策略：把安全检测线程函数替换成"永久睡眠"
//   → 线程正常创建（看门狗满意，不会超时杀 App）
//   → 但线程永远睡觉，永远不执行检测代码

// ── 工具 ──────────────────────────────────────────────────────
function findExport(modName, symName) {
    var mod = Process.findModuleByName(modName);
    if (!mod) return null;
    var addr = null;
    mod.enumerateExports().forEach(function (e) {
        if (e.name === symName) addr = e.address;
    });
    return addr;
}

// ── 永久睡眠线程函数 ──────────────────────────────────────────
// 用全局变量保存，避免被 GC 回收
var _usleepAddr = findExport("libc.so", "usleep");
var _usleep = _usleepAddr ? new NativeFunction(_usleepAddr, 'int', ['uint']) : null;

var sleepForeverFunc = new NativeCallback(function (arg) {
    console.log("[bypass] security thread hijacked — sleeping forever");
    if (_usleep) {
        while (true) { _usleep(10000000); } // 每次睡 10 秒，无限循环
    }
    return ptr(0);
}, 'pointer', ['pointer']);

// ── Part 1: 通过 dlsym 找到 pthread_create 时替换线程函数 ────
function findDlsymReal() {
    var mod = Process.findModuleByName("libdl.so");
    if (!mod) return null;
    var addr = null;
    mod.enumerateExports().forEach(function (e) {
        if (e.name === "dlsym") addr = e.address;
    });
    return addr;
}

var dlsymAddr = findDlsymReal();
if (dlsymAddr) {
    Interceptor.attach(dlsymAddr, {
        onEnter: function (args) {
            try { this.sym = args[1].isNull() ? "" : args[1].readCString(); }
            catch (e) { this.sym = ""; }
        },
        onLeave: function (retval) {
            // 当 msaoaidsec 拿到 pthread_create 函数指针时，
            // 我们不替换指针本身，而是通过 Part2 在实际调用时替换线程函数
        }
    });
    console.log("[+] Part1: dlsym monitored");
}

// ── Part 2: 直接 hook pthread_create，替换线程函数 ────────────
try {
    var pthreadCreateAddr = findExport("libc.so", "pthread_create");
    if (pthreadCreateAddr) {
        Interceptor.attach(pthreadCreateAddr, {
            onEnter: function (args) {
                try {
                    var mod = Process.findModuleByAddress(this.returnAddress);
                    if (mod && mod.name.indexOf("msaoaidsec") !== -1) {
                        console.log("[bypass] pthread_create from msaoaidsec → replacing thread func");
                        // args[2] 是线程函数指针，替换成我们的睡眠函数
                        args[2] = sleepForeverFunc;
                    }
                } catch (e) {}
            }
        });
        console.log("[+] Part2: pthread_create hooked (thread func replacement)");
    }
} catch (e) { console.log("[-] Part2 error: " + e); }

// ── Part 3: strstr 过滤（兜底） ───────────────────────────────
var HIDE = ["frida", "gum-js-loop", "linjector"];
try {
    var strstrAddr = findExport("libc.so", "strstr");
    if (strstrAddr) {
        Interceptor.attach(strstrAddr, {
            onEnter: function (args) {
                this.block = false;
                try {
                    var needle = args[1].readCString();
                    if (needle) {
                        var low = needle.toLowerCase();
                        for (var i = 0; i < HIDE.length; i++) {
                            if (low.indexOf(HIDE[i]) !== -1) { this.block = true; break; }
                        }
                    }
                } catch (e) {}
            },
            onLeave: function (retval) {
                if (this.block) retval.replace(ptr(0));
            }
        });
        console.log("[+] Part3: strstr hooked");
    }
} catch (e) { console.log("[-] Part3 error: " + e); }

// ── Part 4: 拦截 frida-server 端口检测 ───────────────────────
try {
    var connectAddr = findExport("libc.so", "connect");
    if (connectAddr) {
        Interceptor.attach(connectAddr, {
            onEnter: function (args) {
                this.block = false;
                try {
                    var sa = args[1];
                    if (sa.readU16() === 2) {
                        var port = ((sa.add(2).readU8() << 8) | sa.add(3).readU8());
                        if (port === 27042 || port === 27043) {
                            this.block = true;
                            console.log("[bypass] blocked connect to port " + port);
                        }
                    }
                } catch (e) {}
            },
            onLeave: function (retval) {
                if (this.block) retval.replace(ptr(-1));
            }
        });
        console.log("[+] Part4: connect hooked");
    }
} catch (e) { console.log("[-] Part4 error: " + e); }

console.log("[*] bypass_full v4 ready");
