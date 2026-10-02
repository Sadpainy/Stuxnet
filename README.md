# Stuxnet

![Build](https://img.shields.io/badge/Build-unstable-yellow?style=plastic&labelColor=yellow)
![Tests](https://img.shields.io/badge/Tests-passing-brightgreen?style=plastic&labelColor=brightgreen)
![Siemens](https://img.shields.io/badge/Siemens-009999?style=plastic&logo=siemens&logoColor=white)
![Purpose](https://img.shields.io/badge/Purpose-Educational-4CAF50?style=plastic&logo=academia&logoColor=white&labelColor=2E7D32)
![NSA](https://img.shields.io/badge/NSA-007A33?style=plastic&logo=data%3Aimage%2Fpng%3Bbase64%2CiVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAM3ElEQVR4AXRXCXgUVZ7%2FVVVX9Z3uztlJOiH3SYRwxDCKEGEQ8RpAGHQFXd3x25n9dgYvvnVx2KjLzvchx6iDyyC6sjjuKiIqIIMBEggEEo5A7vtO5%2Bj0kT6qj7r2lbu6ozNTX9dX9V699%2Fv93v96r2n8lUtRQCm1tZpvPzclwT55dtMznuZ3P%2Fb3ne6aaDnhn%2Bmpk30Dl2Vff53f13Wqa7b18MeTZ9Y907YG9m%2FnqRgq1rftHz7%2FogDlEzAUBYWqqhKv%2FALFkw273itsutxJF%2Bw45DPdvdGtKS4MmcrMgqWUGoskUmxqpXmaKSjsC%2Bdv1M1745D9t7Wd%2FpZD7%2FXsQ7GKoWKpmD8kV9t%2FJkCpXa6hNkIiH%2Bmpi%2F%2B8d96vb3fYyn%2F%2BdOsEax33KlJr14DU2zegcBwLnZaDxzODYDCIyw2NSktnv9Q7HpA8TLZ1SLzjaduD9R2uhuq9BItRMVVs8v693%2FcEKLXVGqqqTjybj5zI4B%2Fb5Kynngvrc8HpTGJCvFWZcU0yjhQbM7%2FQQfmdXQhM9SKeCyPqG8ayihKqYkEpQ0NmFFFQ3LO8yOvzEEnZ8Jy75aPW%2BgeQo2KrHH%2Bq4DsBqjqqqlpsq8b8ij%2FWtEygsFhkzLG6c2eUEB%2FW5M9JolIMYTj7W7H%2F7d%2FjzYNf4qmt%2B%2FHyrk%2Bx%2FfV38fHHx9HdfBk2LgQOIWrZ8mWarvYWxemJxOLLHisu%2F11tC3HJfJVD5fpWxDcCVP%2Bo6nqqkZO26atL5pyVRpfLJZw%2Fd44ryMuiuptO4Xd7duGOv%2F9vPPT4NbxaI%2BLdbhqtSMYJjwlHBgx4%2BRMf1v2qBTnr38GJz45hrOMSigpyqYpFCzhFUYRw3HyjuerTSy3%2F9H%2BWIHGmiqDVCFX9QxqM9eHDJ6mUJcaLFy8KMUFm1z%2F0Y8yOtmDLq6ex9UAIWnsqytbEAfEkOXgKritTQJBHthnIdGigr7AC2Rn45QE%2FMpftwWRvE8SIH03Xb7JfHD8m2OetN2Zu%2FvQkgP%2BNCQUUjbpahnRg%2BuLLu405q4trL1yKyQrFZtrNOH%2FiCO5%2B8BxmOSvWVsRQSEXQGqCxzjaLtx8RceTgRjy5JAuD3igioLDJPIV%2FTW%2FBqytHMG9JPu5cdRw1xw8j15GArOxctv7y1ZhXk1%2FsrH1%2Bt8qpctNqmvTuRgllv39r94gbnIZiF5WXYWqoDQ9vuYGfbEjASzk3sMp%2BG09n3cYCXQR2UwRzMwJYe%2F9deOHZnwCNflQaedyZ3IpEvR8JmgHcH9eJlAfzsObxy%2Bi9XY%2B0lHhkZaSx1tR8GLI2bh1%2Bi3CSNKdVJSmr3nsxSCcjJcEqlpTOpYaJ%2F1Y%2Bfxza%2BzKxwNgOnvdg1C1CFr0ojgvhnQ8M6KIegtEUB42GQOQZMBnTwMtz6J%2FkMTxDw6pxYgHtAVZmY%2BMrp8FEpjDlclOjwwPimJ%2BFsfK3L4Jc9HUDUhVz0dpAFKitu8BwSghf19RjNmjHaqMfBmYWoqIHy8iIiDp0BXRkWkBNO%2FIEbCY9LKkMIv4wQHHEuRKMOg00tIRikwd6WsSYy4bzdVdh08vo6%2BtjjNYU0PHla68vRCrt%2BPynD0QZm5WhaemOsrkUPzuFVz6fAHK00Mk8orEwZAUQRIBWeKzKjGHDjvvhClNobBvEgIvHxjVL8XBFIqToBGSwECUJY24elOCGVpZgLzHi54e7IRBLLrvnHoqIkIKSyZq37x8eoA321auGnW44neOwJ9vQ2d4Fvo2DlVFgpCMI8BHMzIah1Wox626HMS0TmRV34aO%2BGN7rCOGD7jDiyioQLlkJ90wfDDot%2BIgIvVYHk1ZAAiXBTMtAqw6Dg8NgKBEkxWGzZyPKFa6iY7Rl3vyFS1BcVEQHfS6094wBhQb4RBkmTkKixQg9pyEWkKHQgFWrwVp6EptNXmzWu7HF5MM60l6uC4CzliAYCkKSZRhImdYy0jfkQZGYsMSAlo4RBAmHIAi02xuAPiF%2FHq01JaU1XruOmrNnKZNBi65BN2BhAShgIIDUA1hNHILhCIJyOgyBYaTLPmRoY3DQITjYCOaQd4N3CJPeGSJUIeO1ECRCSrYUjpLJPAJn1aB3xAsxyqOoqJDy%2BQMIhcU0WgFjLCsrQ8XiRYiEebgDEqChCL9CHiTyCQ6pZEg0s7BaM1F%2F6iB8kRhkmkOMmCQmU1A4LdpamxGnCSE%2BTg9JksmtkMogQRUQJvzgaEx6IpBJTJDqiMLCQoiyYiSVUFF4nkdbewdUIppWyYEkIk2WBWJOdTYgk5KpI5Edn21DS1cTIIpQh%2BpJbPT3dWHI2wWjIY9gyGSsOh4IRyMwkexRPUDUQCau0en1uNp4DQ0NV2Awxik0q6FDnZ2dSE5KQnxiMsycBBDzmQh6NCZAJVbXQso5goIePdiAm%2FX7cKv9CkAxmHC7cO3SAUz403ExsJiIikHD0MSBFHQskKoj61fIooiKBBMNo9GM5ORkJcORTlwsh2je5xy%2FY24JFi5cqOiNcSjOSQD8EohlIVFGRGIKWRXhUmKYDlvgFI1IScjA6PQQBjUaTBMylo4hicRNgxAHf8RIRMgAGR9RkjARNcKuUYCghDyHGXFJqcjJnoP8vBwIYc8YHQv0NyckWEAumdLosWBeHtAbRISsrj%2BWDh3xnZ%2BPEREyxsMGpHJRxAK9cOSVoaikAHnElzEqHhZmBqBojIYSiLUjxAI0gjEGZ3k9LGpMNQdQWTEXfCiK1rYOWVLrCz98i%2BZHt50R%2FC709PZhZHwKixbfCSR5IYHGQJRDCHOgoUVEJQ16JBviWQFiDNCbLLBZLbDEmaE1pUBPBVCul9AozMGoC2ApP7xRC0SJQpgYG1mzmF9eDlFhwGhYiLwb%2FNiOM3TPT%2FFV2NPnLi%2B%2Fg8nMyFCSs0vx5rN5mBng4WN0cPp1MFDjaB%2BzYXBWhwzDNExGwEyIjSYTLLZ4pGU4EG%2B8jlyNB0NjLIZsq2EkGZOcngiHgcFIbxhv%2FSwPKTmliDOblJKifCbqHXQPPRo6Ra8BXKGRmqOUGIEgiqKP1PQntjyBFHoYMwINY1YRzPmPIXfFWry5Vot7lliQt3QTKSjD6GhrR2%2FHLdjMM5h39xPYstqAXUR8VUU%2BjnRmImywY4HDCkx0Y%2FOTmzHjDuF8bZ0YmnUjMll%2FtAog2xaAwX2v745Mt2NoZJyddI4r8Y5SnHz7MeBcFxiDGZb8CpTlp4I1J%2BNYcwKQ9TdIK76H%2BFoGzerB5WzC6aH5ONOdiBlPABzZIUtL84kLNPiyuQfXv3gGpuQ8spvGlOzcAlb0diuj%2F7V9N6Em%2B0ttteauz9HvaX3n3xzxHESZEq5cbcKiFZtQc%2FQ%2BHDjRDm8I8PoC6J5ScPAzHtUfXMJbf6jHF%2Bdu48OTN7DzP5vw%2Bslh7G%2BYxa5jo6i9MYrFJQ5EAj58ve1OLLx3AzkVNaNvcERINgF8%2F5HfLHob%2FeoBlcbyaklV4lj9%2FvboSM2NnKx0zuP1Cjebb%2BPeR55Ey7trsf%2FfP8Hze1pw9OYU5lea4Scb1KHzndi%2Brxa7%2FtCIM%2F2TKElkUZbCISvPgq%2BOebDtjaN46YlF%2BPGjz%2BJifQPGx8eF3GwHp3KkrTywXeVUuWmKIhn2iRqmwLXypx6KjZyfqaysZCVJFOqv3EDugpW4ceYNHPxlAoIj%2Fbj15TRGxkie68lS8hOBNBsg69DRH0PrCReGerpxaGcKvFf3YDGxYt2Fy6TEh4WKisWswd88o3Ko5ArhVLlptUGRPyJK7XLNahIunTsfWcK6LrnIiZbldIZYY%2BM1xS9b8LPnf42B09W4eGo19j4eh18U83jUMo11cdN4tsCPfVtsuHDqPnjO78Qz%2F7gNjDULF%2BrqFH8wHJtbWsgmxNpdHdUP%2FEjlqK0l2wzhVLm%2FEaC%2BqMdyVcSPPkTftaKHy2IDxxpLsxM5e%2Focyktc0tc3rPgEIxYsXYPntr%2BCPW%2FswOGDr%2BHD93finf2%2Fwa9e3IaF5FuMTSSnKUGp%2BbpGSE7LpFYsKeX07nON5%2FPXlFV%2BhF6Vo6oKosqp3t8JUBuqCFXdSmAqsfzvKvmW13akacaE0oJMlmG1lMfrl3sHR6VLV27JfeM%2BpbnbifaBabj8stI14JSbbrZKt1s7ZLMljlqxdDHr4CaEwI0d%2FxI%2F728rHyGYirryqrrvyFXO7wlQO1R1SjUpg6SRuvL917teWpYz3fDa3gSxx1nsMNA5jiQmI91OWwmJzWolJyUdotEIlRhvoQuz7MySuWl0sP%2B8M9p1cG%2FX1rtzU1f9x2sECiomVfX%2FK1f71PvPBKidVPU3myClXP89W%2FkZxtLu3f3Cp3kritx1BetjPYcP2PibTXHhNqdDOxHI4JwBW7TDybkvN3ETxw%2FMNhSsV8emLH31hYovMKpiKAooFVPF%2FuH9PwAAAP%2F%2FHipLqAAAAAZJREFUAwDskPlT4MR3pAAAAABJRU5ErkJggg%3D%3D&logoColor=white&labelColor=555555)

This repository contains a strictly educational and research-oriented **reconstruction** of the infamous **Stuxnet** worm. It is the product of countless hours of reverse engineering work conducted by the global security research community on the original binary samples discovered in 2010.

Disclaimer: This code is provided solely for academic study, malware analysis training, and defensive research. **It is not intended to be used for any malicious purposes, nor is it a deployable piece of malware.** The authors and contributors do not condone illegal or unethical activities.

# Table of Contents

Overview

Core Components

Technical Architecture

Build Instructions

Usage

Legal and License

Acknowledgements

# Overview

Stuxnet is widely recognized as the first known cyber-weapon designed to cause physical destruction to industrial control systems (ICS). It specifically targeted Siemens Step 7 software and S7-300/400 PLCs, ultimately manipulating frequency converter drives to damage centrifuge rotors.

This repository is a **reconstructed** source code derived from the decompiled binaries. **It preserves the original logic and attack vectors while structuring the codebase for readability and analysis.**

**Key Characteristics**

**Target: Siemens SIMATIC WinCC, Step 7, and S7 PLCs.**

Propagation: USB drives **(LNK exploits)**, Network shares **(Print Spooler)**, **Peer-to-Peer (P2P).**

Payload: Modification of PLC block logic `(OB1/OB35)` to alter motor frequencies.

Stealth: Advanced Rootkit capabilities `(MRxCls.sys, MRxNet.sys)` for file, process, and registry hiding.

# Core Components

The repository is organized by the primary modules identified during the analysis of the original malware.

Module: Loader/Dropper
Filename: `winsta.exe, ~WTR4141.tmp`
Description: Entry point responsible for initial infection, privilege escalation, and deployment of other components.

Module: Privilege Escalation
Filename: `~WTR4132.tmp`
Description: Exploits the `Win32k.sys` vulnerability to gain system-level privileges.

Module: S7 Hook Library
Filename: `s7otbxdx.dll`
Description: Malicious replacement for the original `s7otbxsx.dll`. It intercepts communication between Step 7 and the PLC.

Module: Step7 Hook Library
Filename: `s7aaapix.dll`
Description: Intercepts AUT (Automation Tool) API calls within the Step 7 engineering environment.

Module: Rootkit (File System)
Filename: `mrxcls.sys`
Description: Kernel-mode driver used to hide Stuxnet files, processes, and registry keys via SSDT hooking.

Module: Rootkit (Network)
Filename: `mrxnet.sys`
Description: Filters file system requests to hide malicious files and enables P2P propagation.

Module: Payload (Attack)
Filename: `s7plcmain`
Description: The core logic responsible for the "Frequency Tampering" attack that damages the centrifuges.

# Technical Architecture

The following describes the high-level execution flow of the Stuxnet framework.

Stage 1: Initial Infection Vector (USB/Network)
Stage 2: Dropper and Escalation
Stage 3: Check Environment
Stage 4a: Target Found (Siemens Software) -> Install S7 Hooks
Stage 4b: Non-target -> Self-Destruct/Idle
Stage 5: Monitor PLC Writes
Stage 6: Detect `OB1/OB35` Write -> Inject Payload
Stage 7: Modify Frequency Output
Stage 8: Physical Damage to Centrifuges
Stage 9: Install Rootkit `(MRxCls)`
Stage 10: Hide Files and Registry
Stage 11: Load Network Module `(MRxNet)`
Stage 12: P2P Propagation

**Execution Flow**

1. Environment Reconnaissance: The worm checks for the presence of specific Siemens software (WinCC, Step 7) and specific target PLCs (S7-315, S7-417).

2. DLL Injection: It intercepts the `s7blk_write` function call.

3. Code Injection: When a user downloads a project to the PLC, the malicious code is appended to the `OB1/OB35` blocks.

4. Physical Impact: The PLC executes the manipulated code, causing the connected variable frequency drives (VFDs) to spin at abnormal frequencies (high/low), resulting in mechanical damage.

**Build Instructions**

**Important: This codebase is designed for static analysis and debugging in a controlled virtual environment. It is not intended for live deployment on any critical infrastructure.**

**Requirements**

Build Environment: **Microsoft Visual Studio 2019/2022 (Windows) or mingw-w64.**

Target OS: **Windows XP / Windows 7 (for driver compatibility).**

Driver Kit:**Windows Driver Kit (WDK) 7600 (if compiling kernel drivers).**

Building the **User-Mode** Modules

**Clone the repository**

```bash
git clone https://github.com/Sadpainy/Stuxnet.git
cd Stuxnet
```

**Build the main dropper**

```bash
cd Main
nmake /f Makefile.win
```

**Build the S7 hook library**

```bash
cd ../s7otbxdx
cl /LD s7otbxdx.c user32.lib ws2_32.lib
```

# Usage

This code is intended for:

**Malware Analysis**: Understanding the specific code logic used in advanced persistent threats (APTs).

**Defensive Research**: Developing detection signatures for ICS security tools (e.g., YARA rules, Snort signatures).

**Academic Study**: Examining the intersection of cybersecurity and critical infrastructure protection.

**Analysis Setup**

1. Isolate Environment: Use a virtual machine (VMWare/VirtualBox) with Host-Only networking enabled. Disable internet connectivity.

2. Load Modules: Analyze the `.dll` and `.sys` files using tools such as IDA Pro, Ghidra, or x64dbg.

3. Monitor Activity: **Use Process Monitor (ProcMon), Process Hacker, and Wireshark to observe the behavior.**

# Legal and License

**License**

This project is licensed under the **GNU Affero General Public License v3.0, LICENSE.Stuxnet, LICENSE.XOR, LICENSE.Detail, Apache License 2.0 and LICENSE.Desktop.** See the LICENSE file for details.

# No Disclaimer. That's on you to be self-aware.

# Acknowledgements

This research and reconstruction would not have been possible without the extensive analysis and threat intelligence provided by global cybersecurity vendors.

**Symantec (W32.Stuxnet dossier)**

**Kaspersky Lab (The Stuxnet saga)**

**ESET (Stuxnet under the microscope)**

**Amr Thabet and Christian Roggia (research-virus/stuxnet)**

```Bash
This is an academic reconstruction. Use it to build stronger defenses, not to cause harm.
```
