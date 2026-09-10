# Stuxnet

![Build Unstable](https://img.shields.io/badge/build-unstable-yellow?style=plastic)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=plastic&logo=windows&logoColor=white)
![Siemens](https://img.shields.io/badge/Siemens-009999?style=plastic&logo=siemens&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-passing-brightgreen?style=plastic&labelColor=555555)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=plastic&logo=linux&logoColor=black)

This repository contains a strictly educational and research-oriented reconstruction of the infamous Stuxnet worm. It is the product of countless hours of reverse engineering work conducted by the global security research community on the original binary samples discovered in 2010.

Disclaimer: This code is provided solely for academic study, malware analysis training, and defensive research. It is not intended to be used for any malicious purposes, nor is it a deployable piece of malware. The authors and contributors do not condone illegal or unethical activities.

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

This repository is a reconstructed source code derived from the decompiled binaries. It preserves the original logic and attack vectors while structuring the codebase for readability and analysis.

**Key Characteristics**

Target: Siemens SIMATIC WinCC, Step 7, and S7 PLCs.

Propagation: USB drives (LNK exploits), Network shares (Print Spooler), Peer-to-Peer (P2P).

Payload: Modification of PLC block logic (OB1/OB35) to alter motor frequencies.

Stealth: Advanced Rootkit capabilities (MRxCls.sys, MRxNet.sys) for file, process, and registry hiding.

# Core Components

The repository is organized by the primary modules identified during the analysis of the original malware.

Module: Loader/Dropper
Filename: winsta.exe, ~WTR4141.tmp
Description: Entry point responsible for initial infection, privilege escalation, and deployment of other components.

Module: Privilege Escalation
Filename: ~WTR4132.tmp
Description: Exploits the Win32k.sys vulnerability to gain system-level privileges.

Module: S7 Hook Library
Filename: s7otbxdx.dll
Description: Malicious replacement of the original s7otbxsx.dll. Intercepts communication between Step 7 and the PLC.

Module: Step7 Hook Library
Filename: s7aaapix.dll
Description: Intercepts AUT (Automation Tool) API calls within the Step 7 engineering environment.

Module: Rootkit (File System)
Filename: mrxcls.sys
Description: Kernel-mode driver used to hide Stuxnet files, processes, and registry keys via SSDT hooking.

Module: Rootkit (Network)
Filename: mrxnet.sys
Description: Filters file system requests to hide malicious files and enables P2P propagation.

Module: Payload (Attack)
Filename: s7plcmain
Description: The core logic responsible for the "Frequency Tampering" attack that damages the centrifuges.

# Technical Architecture

The following describes the high-level execution flow of the Stuxnet framework.

Stage 1: Initial Infection Vector (USB/Network)
Stage 2: Dropper and Escalation
Stage 3: Check Environment
Stage 4a: Target Found (Siemens Software) -> Install S7 Hooks
Stage 4b: Non-target -> Self-Destruct/Idle
Stage 5: Monitor PLC Writes
Stage 6: Detect OB1/OB35 Write -> Inject Payload
Stage 7: Modify Frequency Output
Stage 8: Physical Damage to Centrifuges
Stage 9: Install Rootkit (MRxCls)
Stage 10: Hide Files and Registry
Stage 11: Load Network Module (MRxNet)
Stage 12: P2P Propagation

**Execution Flow**

1. Environment Reconnaissance: The worm checks for the presence of specific Siemens software (WinCC, Step 7) and specific target PLCs (S7-315, S7-417).

2. DLL Injection: It intercepts the s7blk_write function call.

3. Code Injection: When a user downloads a project to the PLC, the malicious code is appended to the OB1/OB35 blocks.

4. Physical Impact: The PLC executes the manipulated code, causing the connected variable frequency drives (VFDs) to spin at abnormal frequencies (high/low), resulting in mechanical damage.

**Build Instructions**

Important: This codebase is designed for static analysis and debugging in a controlled virtual environment. It is not intended for live deployment on any critical infrastructure.

**Requirements**

Build Environment: Microsoft Visual Studio 2019/2022 (Windows) or mingw-w64.

Target OS: Windows XP / Windows 7 (for driver compatibility).

Driver Kit: Windows Driver Kit (WDK) 7600 (if compiling kernel drivers).

Building the User-Mode Modules

**Clone the repository**

```bash
git clone https://github.com/Sadpainy/Stuxnet.git
cd Stuxnet
```

**Build the main dropper**

```bash
cd winsta
nmake /f Makefile.win
```

**Build the S7 hook library**

```bash
cd ../s7otbxdx
cl /LD s7otbxdx.c user32.lib ws2_32.lib
```

# Usage

This code is intended for:

Malware Analysis: Understanding the specific code logic used in advanced persistent threats (APTs).

Defensive Research: Developing detection signatures for ICS security tools (e.g., YARA rules, Snort signatures).

Academic Study: Examining the intersection of cybersecurity and critical infrastructure protection.

**Analysis Setup**

1. Isolate Environment: Use a virtual machine (VMWare/VirtualBox) with Host-Only networking enabled. Disable internet connectivity.

2. Load Modules: Analyze the .dll and .sys files using tools such as IDA Pro, Ghidra, or x64dbg.

3. Monitor Activity: Use Process Monitor (ProcMon), Process Hacker, and Wireshark to observe the behavior.

# Legal and License

**License**

This project is licensed under the GNU General Public License v3.0. See the LICENSE file for details.

# Disclaimer

The code in this repository is a product of reverse engineering for educational purposes only. The original authors of the Stuxnet worm are anonymous, but the reconstruction contained herein is the work of independent security researchers.

The authors do not claim ownership of the original malware.

The code is provided "AS IS" without warranty of any kind.

The authors are not responsible for any misuse or damage caused by this code.

By using this repository, you acknowledge that you are solely responsible for ensuring compliance with all applicable laws and regulations.

# Acknowledgements

This research and reconstruction would not have been possible without the extensive analysis and threat intelligence provided by global cybersecurity vendors.

**Symantec (W32.Stuxnet dossier)**

**Kaspersky Lab (The Stuxnet saga)**

**ESET (Stuxnet under the microscope)**

**Amr Thabet and Christian Roggia (research-virus/stuxnet)**

This is an academic reconstruction. Use it to build stronger defenses, not to cause harm.
