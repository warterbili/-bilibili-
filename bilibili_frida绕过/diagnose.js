// 诊断脚本：找出 dlsym 的真实位置，以及哪些函数可以被 hook

// 1. 测试 Interceptor.attach 是否能工作（用 malloc 做基准测试）
console.log("=== 测试 Interceptor.attach 是否正常 ===");
try {
    var malloc = Module.findExportByName("libc.so", "malloc");
    Interceptor.attach(malloc, { onEnter: function() {} });
    console.log("[+] libc malloc 可以 hook @ " + malloc);
    Interceptor.detachAll();
} catch(e) {
    console.log("[-] malloc hook 失败: " + e);
}

// 2. 找 dlsym 在所有模块中的位置
console.log("\n=== 查找 dlsym 在哪些模块中 ===");
Process.enumerateModules().forEach(function(mod) {
    try {
        mod.enumerateExports().forEach(function(exp) {
            if (exp.name === "dlsym" || exp.name === "__dl_dlsym" || exp.name === "__dlsym") {
                console.log("[*] " + mod.name + " -> " + exp.name + " @ " + exp.address + " type=" + exp.type);
                // 尝试 hook
                try {
                    Interceptor.attach(exp.address, { onEnter: function() {} });
                    console.log("    [+] 可以 hook!");
                    Interceptor.detachAll();
                } catch(e2) {
                    console.log("    [-] hook 失败: " + e2);
                }
            }
        });
    } catch(e) {}
});

// 3. 列出 linker64 的部分 exports（找检测相关的）
console.log("\n=== linker64 导出函数（含 dl 关键词）===");
var linker = Process.findModuleByName("linker64");
if (linker) {
    console.log("linker64 base: " + linker.base);
    linker.enumerateExports().forEach(function(exp) {
        if (exp.name.toLowerCase().includes("dlsym") ||
            exp.name.toLowerCase().includes("dlopen")) {
            console.log("  " + exp.name + " @ " + exp.address);
        }
    });
} else {
    console.log("[-] linker64 not found");
}

console.log("\n=== 诊断完成 ===");
