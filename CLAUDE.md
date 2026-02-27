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

- MD files in the root directory are learning notes documenting the reverse engineering journey.
- Key docs: `flashing_guide.md` (BL unlock), `miui_to_pixel.md` (ROM flashing)

## Environment

- Target device: Xiaomi Mi 9 (cepheus), running PixelExperience 13.0
- ADB/Fastboot path: Android SDK Platform Tools
- Key tools: adb, fastboot, scrcpy, v2rayNG
