// hook_sprintf.js - 捕获 libbili.so 内 sprintf 调用的格式字符串
// 目的：确认 DAT_001d8844 和 DAT_001d8cbc 的真实格式字符串

var libbiliBase = null;
var libbiliEnd = null;

// 等 libbili.so 加载
function tryHook() {
    var mod = Process.findModuleByName("libbili.so");
    if (!mod) return false;
    libbiliBase = mod.base;
    libbiliEnd = mod.base.add(mod.size);
    console.log("[+] libbili.so: " + libbiliBase + " ~ " + libbiliEnd);

    // 找 libc.so 里的 sprintf
    var sprintfAddr = null;
    var libc = Process.findModuleByName("libc.so");
    libc.enumerateExports().forEach(function(e) {
        if (e.name === "sprintf") sprintfAddr = e.address;
    });

    if (!sprintfAddr) {
        console.log("[-] sprintf not found");
        return false;
    }
    console.log("[+] sprintf @ " + sprintfAddr);

    Interceptor.attach(sprintfAddr, {
        onEnter: function(args) {
            // 只关注从 libbili.so 发起的调用
            var caller = this.returnAddress;
            if (caller.compare(libbiliBase) < 0 || caller.compare(libbiliEnd) >= 0) return;

            try {
                var fmt = args[1].readCString();
                var offset = caller.sub(libbiliBase);
                console.log("[sprintf] caller=+0x" + offset.toString(16) + " fmt=\"" + fmt + "\"");
            } catch(e) {}
        }
    });

    console.log("[+] sprintf hooked，发一条评论触发...");
    return true;
}

var hooked = false;
var count = 0;
var poller = setInterval(function() {
    if (!hooked) hooked = tryHook();
    if (++count >= 30) clearInterval(poller);
}, 500);

console.log("[*] hook_sprintf.js ready");
