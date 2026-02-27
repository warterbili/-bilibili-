// ==UserScript==
// @name         拦截所有跳转和新开页面
// @namespace    http://tampermonkey.net/
// @version      1.2
// @description  拦截 window.open、location 跳转，打印堆栈并弹窗暂停
// @match        *://*.njavtv.com/*
// @match        *://njavtv.com/*
// @run-at       document-start
// @grant        none
// ==/UserScript==

(function() {
    'use strict';

    // 1. 拦截 window.open（新开标签页）
    const originalOpen = window.open;
    window.open = function(url, target, features) {
        console.log('%c[拦截] window.open', 'color: red; font-size: 16px;', url);
        console.trace('[堆栈] window.open 调用来源');
        alert('[拦截] window.open\n目标: ' + url);
        return null;
    };

    // 2. 拦截 location.href 赋值（当前页面跳转）
    const originalLocation = Object.getOwnPropertyDescriptor(window, 'location')
        || Object.getOwnPropertyDescriptor(Window.prototype, 'location');

    if (originalLocation && originalLocation.set) {
        Object.defineProperty(window, 'location', {
            get: originalLocation.get,
            set: function(url) {
                console.log('%c[拦截] location.href =', 'color: red; font-size: 16px;', url);
                console.trace('[堆栈] location.href 调用来源');
                alert('[拦截] location.href\n目标: ' + url);
            },
            configurable: true
        });
    }

    // 3. 拦截 location.assign / location.replace
    const origAssign = Location.prototype.assign;
    const origReplace = Location.prototype.replace;

    Location.prototype.assign = function(url) {
        console.log('%c[拦截] location.assign', 'color: red; font-size: 16px;', url);
        console.trace('[堆栈] location.assign 调用来源');
        alert('[拦截] location.assign\n目标: ' + url);
    };

    Location.prototype.replace = function(url) {
        console.log('%c[拦截] location.replace', 'color: red; font-size: 16px;', url);
        console.trace('[堆栈] location.replace 调用来源');
        alert('[拦截] location.replace\n目标: ' + url);
    };

    // 4. 拦截动态创建的 <a> 标签点击跳转
    document.addEventListener('click', function(e) {
        const a = e.target.closest('a');
        if (a && a.href && a.target === '_blank') {
            console.log('%c[拦截] <a> 新标签页', 'color: orange; font-size: 16px;', a.href);
            console.trace('[堆栈] <a> 点击来源');
            alert('[拦截] <a> 新标签页\n目标: ' + a.href);
            e.preventDefault();
            e.stopPropagation();
        }
    }, true);

    // 5. 监控动态插入的 <script> 标签 —— 找出广告脚本来源
    const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(m) {
            m.addedNodes.forEach(function(node) {
                if (node.tagName === 'SCRIPT' && node.src) {
                    console.log('%c[新脚本加载]', 'color: blue; font-size: 14px;', node.src);
                }
            });
        });
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });

    console.log('%c[跳转拦截脚本 v1.2 已注入]', 'color: green; font-size: 14px;');
})();
