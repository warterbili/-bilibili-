// find_registernatives.js - 找 libart.so 里 RegisterNatives 的真实导出名

var libart = Process.findModuleByName("libart.so");
if (!libart) {
    console.log("[-] libart.so not found");
} else {
    console.log("[+] libart.so base: " + libart.base);
    console.log("[*] 搜索 RegisterNatives...");

    var found = [];
    libart.enumerateExports().forEach(function(e) {
        if (e.name.toLowerCase().indexOf("registernative") !== -1) {
            found.push(e);
        }
    });

    if (found.length === 0) {
        console.log("[-] 在 exports 里没找到，尝试 symbols...");
        libart.enumerateSymbols().forEach(function(s) {
            if (s.name.toLowerCase().indexOf("registernative") !== -1) {
                console.log("  [sym] " + s.name + " @ " + s.address);
            }
        });
    } else {
        found.forEach(function(e) {
            console.log("  [exp] " + e.name + " @ " + e.address);
        });
    }
}
