# Offensive security scripts

This repository contains my personal collection of write-ups, exploit scripts, and solutions developed for the **Offensive Security** course, part of my Master's Degree in Cybersecurity Engineering at Politecnico di Torino.

The goal of this repository is to document my practical learning journey in vulnerability analysis, reverse engineering, and exploit development, moving from theoretical concepts to hands-on application.

## 📂 Repository Structure

To keep things organized, the repository is divided into the following main sections. Each folder contains its own detailed README:

* **`📁 web/`**
  Contains challenges and scripts related to Web Application Security. Focuses on exploiting common vulnerabilities such as SQL Injection, Cross-Site Scripting (XSS), and logic flaws. 
* **`📁 BIN/`**
  Dedicated to Binary Exploitation and Low-Level Security. Includes exploits for memory corruption vulnerabilities, Buffer Overflows, and Return-Oriented Programming (ROP) chains.
* **`📁 python/`**
  Contains information regarding my local Python environment setup and the core libraries (like `pwntools` and `requests`) used to automate the exploits across all categories.

Below is the visual hierarchy of the repository:

```text
📦 offensive-security-scripts
 ┣ 📂 BIN
 ┣ 📂 python
 ┗ 📂 web
```

## 🏆 Highlighted Challenges

Here are some of the most interesting and complex challenges I solved during the course.

### ⚙️ Binary Exploitation
* **[Weather Station](./BIN/lab02/challenges/05_weather_station) - [Buffer Overflow & Stack Canary Bypass]:** Exploited a buffer overflow vulnerability in a forking network server. Successfully bypassed the Stack Canary protection by performing a byte-by-byte brute-force attack, leveraging the fact that child processes inherit the parent's canary value. Hijacked the execution flow via a ret2win attack to spawn a remote shell.
* **[Parrot Cage](./BIN/bin_recap/recap_3) - [Buffer Overflow & Info Leak (Canary)]:** Exploited a buffer overflow within a continuous echo loop to leak the Stack Canary. By intentionally overwriting the canary's null byte, I forced the `puts` function to reveal the remaining protector bytes. After reconstructing the full canary, I bypassed the mitigation and executed a ret2win attack, incorporating a `ret` gadget for proper stack alignment.
* **[Postcard Writer](./BIN/lab03/challenges/04_postcard-writer) - [Buffer Overflow & Ret2Libc (ASLR Bypass)]:** Exploited a buffer overflow by constructing a two-stage Return-Oriented Programming (ROP) chain. In the first stage, I leaked the ASLR-randomized `libc` base address by executing a `pop rdi` gadget to print the GOT entry of the `read` function, then seamlessly returned to `main`. In the second stage, I used the calculated offsets to redirect execution to `system('/bin/sh')` and gain a remote shell.

### 🌐 Web Exploitation
### 🌐 Web Exploitation
* **[FlagMail](./web/flagmail.py) - [Predictable Session Token & Session Hijacking]:** Exploited a logic flaw in the authentication mechanism where session tokens were insecurely generated using predictable Unix timestamps concatenated with a user ID. By reverse-engineering the token structure and brute-forcing a narrow 60-second time window, I successfully predicted the admin's authorization token to hijack their session and exfiltrate confidential data via the API.
* **[VirusVault](./web/command_injection.py) - [Blind Command Injection (Time-based)]:** Exploited a command injection vulnerability in a file upload system where the application poorly sanitized filenames before passing them to the underlying shell. Since the server response did not display the command output, I developed a Python script to perform a time-based, character-by-character brute-force attack to extract the `FLAG` environment variable using conditional sleep delays.
