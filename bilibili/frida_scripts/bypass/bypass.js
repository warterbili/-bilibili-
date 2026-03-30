// 绕过 B站 libmsaoaidsec.so 反 Frida 检测
// 关键修复：用 enumerateExports() 找 dlsym 真实地址
//           Module.findExportByName() 返回的是 PLT stub 无法 hook

var fakeFunc = new NativeCallback(function() {
    console.log("[+] fake pthread_create called, suppressed");
    return 0;
}, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
console.log("[*] Fake function @ " + fakeFunc);

// 通过 enumerateExports 找到可 hook 的真实 dlsym 地址
function findDlsymReal() {
    var libdl = Process.findModuleByName("libdl.so");
    if (!libdl) { console.log("[-] libdl.so not found"); return null; }
    var addr = null;
    libdl.enumerateExports().forEach(function(exp) {
        if (exp.name === "dlsym") addr = exp.address;
    });
    return addr;
}

var dlsymAddr = findDlsymReal();
if (!dlsymAddr) {
    console.log("[-] dlsym not found, abort");
} else {
    console.log("[+] dlsym real address: " + dlsymAddr);
    try {
        Interceptor.attach(dlsymAddr, {
            onEnter: function(args) {
                try {
                    this.symbol = args[1].isNull() ? "" : args[1].readCString();
                } catch(e) { this.symbol = ""; }
            },
            onLeave: function(retval) {
                if (this.symbol === "pthread_create" || this.symbol === "pthread_join") {
                    try {
                        var mod = Process.findModuleByAddress(this.returnAddress);
                        if (mod && mod.name.indexOf("msaoaidsec") !== -1) {
                            console.log("[+] Blocked dlsym(\"" + this.symbol + "\") from " + mod.name);
                            retval.replace(fakeFunc);
                        }
                    } catch(e) { console.log("[-] handler error: " + e); }
                }
            }
        });
        console.log("[+] dlsym hooked successfully");
    } catch(e) {
        console.log("[-] Failed to hook dlsym: " + e);
    }
}

console.log("[*] bypass ready");
