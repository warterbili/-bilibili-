// debug_pthread.js - 追踪所有 pthread_create 调用来源
// 只运行几秒，看看 msaoaidsec 是否出现在调用链里

function findExport(modName, symName) {
    var mod = Process.findModuleByName(modName);
    if (!mod) return null;
    var addr = null;
    mod.enumerateExports().forEach(function (e) {
        if (e.name === symName) addr = e.address;
    });
    return addr;
}

var pthreadCreateAddr = findExport("libc.so", "pthread_create");
console.log("[*] pthread_create @ " + pthreadCreateAddr);

if (pthreadCreateAddr) {
    var count = 0;
    Interceptor.attach(pthreadCreateAddr, {
        onEnter: function (args) {
            if (count++ > 60) return; // 只记录前60次
            try {
                var retAddr = this.returnAddress;
                var mod = Process.findModuleByAddress(retAddr);
                var modName = mod ? mod.name : "unknown";
                // 只打印非系统库的调用
                if (modName.indexOf("com.android") === -1 &&
                    modName.indexOf("libart") === -1 &&
                    modName.indexOf("libc") === -1) {
                    console.log("[pthread_create] from=" + modName +
                                " retAddr=" + retAddr +
                                " threadFunc=" + args[2]);
                }
            } catch (e) {
                console.log("[pthread_create] error: " + e);
            }
        }
    });
    console.log("[+] pthread_create hooked, waiting for calls...");
}
