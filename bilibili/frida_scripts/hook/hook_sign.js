// hook_sign.js v2 - 通过 art::ClassLinker::RegisterNative 捕获 libbili.so 的 native 函数
// 不使用 Java.perform，纯 Native Hook

var libbiliBase = null;
var libbiliSize = 0;
var capturedFuncs = [];

// ── 等 libbili.so 加载，记录地址范围 ─────────────────────────
function getLibbiliRange() {
    var mod = Process.findModuleByName("libbili.so");
    if (!mod) return false;
    libbiliBase = mod.base;
    libbiliSize = mod.size;
    console.log("[+] libbili.so 范围: " + libbiliBase + " ~ " + libbiliBase.add(libbiliSize));
    return true;
}

// ── 判断地址是否在 libbili.so 内 ──────────────────────────────
function inLibbili(addr) {
    if (!libbiliBase) return false;
    return addr.compare(libbiliBase) >= 0 &&
           addr.compare(libbiliBase.add(libbiliSize)) < 0;
}

// ── Hook art::ClassLinker::RegisterNative ─────────────────────
// 签名: RegisterNative(ClassLinker*, Thread*, ArtMethod*, void* fnPtr)
// args[0]=this, args[1]=Thread*, args[2]=ArtMethod*, args[3]=fnPtr
var libart = Process.findModuleByName("libart.so");
var regNativeAddr = null;
libart.enumerateExports().forEach(function(e) {
    if (e.name === "_ZN3art11ClassLinker14RegisterNativeEPNS_6ThreadEPNS_9ArtMethodEPKv") {
        regNativeAddr = e.address;
    }
});

if (!regNativeAddr) {
    console.log("[-] RegisterNative not found");
} else {
    console.log("[+] RegisterNative @ " + regNativeAddr);

    Interceptor.attach(regNativeAddr, {
        onEnter: function(args) {
            var fnPtr = args[3];

            // 先尝试更新 libbili.so 范围（可能此时刚加载）
            if (!libbiliBase) getLibbiliRange();

            if (libbiliBase && inLibbili(fnPtr)) {
                var offset = fnPtr.sub(libbiliBase);
                console.log("[+] libbili.so native 方法注册: fnPtr=" + fnPtr + " offset=+0x" + offset.toString(16));
                capturedFuncs.push(fnPtr);
            }
        }
    });

    console.log("[+] RegisterNative hooked，等待 libbili.so 方法注册...");
}

// ── 15秒后输出所有捕获的函数，并附加 Hook ────────────────────
setTimeout(function() {
    if (capturedFuncs.length === 0) {
        console.log("[-] 没有捕获到 libbili.so 的任何 native 方法");
        return;
    }

    console.log("\n[*] 共捕获 " + capturedFuncs.length + " 个 libbili.so native 方法，逐个附加...");
    capturedFuncs.forEach(function(addr, i) {
        var offset = addr.sub(libbiliBase);
        try {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    console.log("\n>>> 方法 #" + i + " 被调用! addr=" + addr + " offset=+0x" + offset.toString(16));
                },
                onLeave: function(retval) {
                    console.log("<<< 方法 #" + i + " 返回: " + retval);
                }
            });
            console.log("  [+] #" + i + " attached: " + addr + " (+0x" + offset.toString(16) + ")");
        } catch(e) {
            console.log("  [-] #" + i + " attach 失败: " + e);
        }
    });

    console.log("\n[*] 现在发一条评论，看哪个方法被调用...");
}, 15000);

console.log("[*] hook_sign.js v2 ready");
