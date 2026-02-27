// ==UserScript==
// @name         追踪跳转来源（不拦截）
// @namespace    http://tampermonkey.net/
// @version      1.0
// @description  只记录跳转堆栈，不阻止任何行为
// @match        *://*.njavtv.com/*
// @match        *://njavtv.com/*
// @run-at       document-start
// @grant        none
// ==/UserScript==

(function() {
    'use strict';

    // 1. 追踪 window.open（不拦截）
    const originalOpen = window.open;
    window.open = function(url, target, features) {
        console.log('%c[追踪] window.open', 'color: red; font-size: 16px;', url);
        console.trace('[堆栈] window.open 调用来源');
        return originalOpen.call(this, url, target, features); // 正常执行
    };

    // 2. 追踪 location.assign / location.replace（不拦截）
    const origAssign = Location.prototype.assign;
    const origReplace = Location.prototype.replace;

    Location.prototype.assign = function(url) {
        console.log('%c[追踪] location.assign', 'color: red; font-size: 16px;', url);
        console.trace('[堆栈] location.assign 调用来源');
        origAssign.call(this, url); // 正常执行
    };

    Location.prototype.replace = function(url) {
        console.log('%c[追踪] location.replace', 'color: red; font-size: 16px;', url);
        console.trace('[堆栈] location.replace 调用来源');
        origReplace.call(this, url); // 正常执行
    };

    // 3. 追踪 <a> 点击（不拦截）
    document.addEventListener('click', function(e) {
        const a = e.target.closest('a');
        if (a && a.href) {
            console.log('%c[追踪] <a> 点击', 'color: orange; font-size: 16px;',
                'href:', a.href, 'target:', a.target);
            console.trace('[堆栈] <a> 点击来源');
            // 不调用 preventDefault，让它正常跳转
        }
    }, true);

    // 4. 监控动态插入的 <script>
    const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(m) {
            m.addedNodes.forEach(function(node) {
                if (node.tagName === 'SCRIPT' && node.src) {
                    console.log('%c[新脚本]', 'color: blue; font-size: 14px;', node.src);
                }
            });
        });
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });

    console.log('%c[跳转追踪脚本 v1.0 已注入 - 仅记录不拦截]', 'color: green; font-size: 14px;');
})();
