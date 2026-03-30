# CLAUDE.md

## Communication Style

- Keep responses concise and brief to minimize token usage.
- Respond quickly and avoid excessive deep thinking that over-consumes tokens.

## Context Management

- When the conversation context reaches a significant length, proactively remind the user to compress the context to reduce token consumption.

## Skills Documents

- Load skills documents on demand as needed, but always ask for user consent before reading them, unless the user explicitly requests it.

## Language

- Respond in Chinese (中文) by default.

## Project Overview

- This project is focused on learning Android app reverse engineering.
- Primary coding languages: Python, Java, and Node.js.

## Project Structure

- `docs/` — 通用安卓逆向教程（按学习顺序编号：刷机→工具→反编译→系统知识→自动化）
- `bilibili/` — Bilibili 逆向实战（docs/实战笔记、frida_scripts/Frida脚本、sign_verify/签名验证、auto_comment/自动评论、packet_capture/抓包数据、mitmproxy/中间人代理）
- `bilibili/frida_scripts/` — 按功能分为 bypass/hook/trace/debug 四类
- `android_automation/` — 安卓自动化（UIAutomator2）
- `tools/` — 通用工具脚本（Tampermonkey userscripts）

## Environment

- Target device: Xiaomi Mi 9 (cepheus), running PixelExperience 13.0
- ADB/Fastboot path: Android SDK Platform Tools
- Key tools: adb, fastboot, scrcpy, v2rayNG
